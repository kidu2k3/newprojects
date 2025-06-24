import os
import socket
import json
import threading
import time
import random
import sys
import base64

from key_exchange import KeyExchange
from onion_crypto_utils import OnionCrypto

RELAY_TCP_HOST = "193.37.138.26"
RELAY_TCP_PORT = 42069
RELAY_UDP_HOST = "193.37.138.26"
RELAY_UDP_PORT = 42069
CHUNK_SIZE = 3072

class Client:
    def __init__(self):
        self.client_id = self.generate_ipv6_id()
        self.tcp_sock = None
        self.udp_sock = None
        self.is_connected = False
        self.peer_sessions = {}
        self.active_peer = None
        self.relay_udp_addr = (RELAY_UDP_HOST, RELAY_UDP_PORT)
        self.ui_lock = threading.Lock()
        self.pending_sent_offers = {}
        self.crypto_utility = OnionCrypto()

        if not self.crypto_utility.self_test():
            print("[!!!] CRITICAL: Cryptography self-test failed. Exiting.")
            sys.exit(1)
        else:
            print("[*] Cryptography self-test passed.")

        print(f"[*] Your AltNet IPv6 is: {self.client_id}")

    def generate_ipv6_id(self):
        prefix = "fd00:dead:beef:cafe::"
        suffix = os.urandom(2).hex()
        return prefix + suffix

    def connect_to_relay(self):
        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.connect((RELAY_TCP_HOST, RELAY_TCP_PORT))
            self.tcp_sock.sendall(json.dumps({"type": "client_hello", "id": self.client_id}).encode())

            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.bind(('0.0.0.0', 0))

            self.is_connected = True

            tcp_thread = threading.Thread(target=self.tcp_listener_loop, daemon=True)
            udp_thread = threading.Thread(target=self.udp_p2p_listener_loop, daemon=True)
            keep_alive_thread = threading.Thread(target=self.udp_keep_alive_loop, daemon=True)

            tcp_thread.start()
            udp_thread.start()
            keep_alive_thread.start()

            self.print_ui(f"[*] Connected to the AltNet relay at {RELAY_TCP_HOST}.")
            return True
        except Exception as e:
            self.print_ui(f"[!] Failed to connect to relay: {e}")
            return False

    def udp_keep_alive_loop(self):
        ping_payload = json.dumps({"type": "udp_ping", "from": self.client_id}).encode()
        while self.is_connected:
            try:
                if self.udp_sock:
                    self.udp_sock.sendto(ping_payload, self.relay_udp_addr)
            except Exception:
                pass
            time.sleep(5)

    def tcp_listener_loop(self):
        while self.is_connected:
            try:
                if not self.tcp_sock:
                    break
                data = self.tcp_sock.recv(4096)
                if not data:
                    break
                message = json.loads(data.decode())

                if message.get("type") == "scan_result":
                    self.display_scan_results(message["peers"])
                elif message.get("type") == "punch_info":
                    self.start_hole_punching(message["peer_id"], tuple(message["addr"]))
                elif message.get("type") == "punch_error":
                    self.print_ui(f"[!] Relay error: {message['reason']}")
            except (socket.error, ConnectionResetError, BrokenPipeError, json.JSONDecodeError):
                break
            except Exception:
                break
        self.is_connected = False
        if self.tcp_sock:
            try:
                self.tcp_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.tcp_sock.close()
            self.tcp_sock = None
        self.print_ui("[!] TCP connection to relay lost.")

    def udp_p2p_listener_loop(self):
        while self.is_connected:
            try:
                if not self.udp_sock:
                    break
                data, addr = self.udp_sock.recvfrom(CHUNK_SIZE + 4096)

                try:
                    raw_message_str = data.decode()
                    message_envelope = json.loads(raw_message_str)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                sender_id_outer = message_envelope.get("from_id_outer")

                if "payload" in message_envelope:
                    session_lookup_id = sender_id_outer
                    if not session_lookup_id:
                        continue

                    session = self.peer_sessions.get(session_lookup_id)
                    if session and session.get("shared_key"):
                        try:
                            decrypted_payload_bytes = self.crypto_utility.decrypt_layer(
                                message_envelope["payload"], session["shared_key"]
                            )
                            message = json.loads(decrypted_payload_bytes.decode())

                            sender_id_inner = message.get("from")
                            if sender_id_inner != session_lookup_id:
                                self.print_ui(
                                    f"[!] Sender ID mismatch! Outer: {session_lookup_id}, Inner: {sender_id_inner}. Message from {addr} dropped."
                                )
                                continue

                            if session.get("addr") != addr:
                                session["addr"] = addr
                            self.process_direct_message(session_lookup_id, message, addr)
                        except Exception as e:
                            self.print_ui(
                                f"[!] Error decrypting/processing message from {session_lookup_id} ({addr}): {e}"
                            )
                    else:
                        pass
                else:
                    message = message_envelope
                    msg_type = message.get("type")
                    actual_sender_id = message.get("from")
                    if not actual_sender_id:
                        continue

                    if msg_type == "udp_pong":
                        continue

                    if msg_type == "punch_knock":
                        ack_payload = {"type": "punch_ack", "from": self.client_id}
                        if self.udp_sock:
                            self.udp_sock.sendto(json.dumps(ack_payload).encode(), addr)
                        current_session = self.peer_sessions.get(actual_sender_id, {})
                        if current_session.get("state") not in [
                            "secured",
                            "key_exchanging",
                            "key_exchange_sent",
                            "punch_acked",
                            "punch_received",
                        ]:
                            self.print_ui(
                                f"[+] UDP Hole Punch knock from {actual_sender_id} ({addr}). Will respond to key exchange."
                            )
                            self.peer_sessions[actual_sender_id] = {
                                "state": "punch_received",
                                "addr": addr,
                                "key_exchange_instance": KeyExchange(),
                                "is_initiator": False,
                                "pending_file_offers": {},
                                "incoming_file_details": None,
                            }

                    elif msg_type == "punch_ack":
                        session = self.peer_sessions.get(actual_sender_id)
                        if (
                            session
                            and session.get("state") == "punching"
                            and session.get("is_initiator")
                        ):
                            self.print_ui(
                                f"[+] UDP Hole Punch ack from {actual_sender_id} ({addr})! Initiating key exchange."
                            )
                            session["state"] = "punch_acked"
                            session["addr"] = addr
                            if not self.active_peer:
                                self.active_peer = actual_sender_id
                            self.send_key_exchange_init(actual_sender_id)

                    elif msg_type == "key_exchange_init":
                        self.handle_key_exchange_init(actual_sender_id, message, addr)

                    elif msg_type == "key_exchange_ack":
                        self.handle_key_exchange_ack(actual_sender_id, message, addr)

            except socket.error:
                if self.is_connected and self.udp_sock:
                    pass
                break
            except Exception:
                pass

    def start_hole_punching(self, peer_id, peer_addr):
        self.print_ui(f"[*] Instructed to hole punch with {peer_id} at {peer_addr}.")
        self.peer_sessions[peer_id] = {
            "state": "punching",
            "addr": peer_addr,
            "key_exchange_instance": KeyExchange(),
            "is_initiator": True,
            "pending_file_offers": {},
            "incoming_file_details": None,
        }

        def punch_thread_worker():
            for _ in range(7):
                session = self.peer_sessions.get(peer_id)
                if not session or session.get("state") != "punching":
                    break
                payload = {"type": "punch_knock", "from": self.client_id}
                try:
                    if self.udp_sock:
                        self.udp_sock.sendto(json.dumps(payload).encode(), peer_addr)
                except Exception as e:
                    self.print_ui(f"[!] Error sending punch knock to {peer_id}: {e}")
                    break
                time.sleep(random.uniform(0.2, 0.6))

            time.sleep(1.5)
            session = self.peer_sessions.get(peer_id)
            if session and session.get("state") == "punching":
                self.print_ui(
                    f"[!] Hole punch to {peer_id} might have failed (no ack after knocks)."
                )
                session["state"] = "punch_failed"

        threading.Thread(target=punch_thread_worker, daemon=True).start()

    def send_key_exchange_init(self, peer_id):
        session = self.peer_sessions.get(peer_id)
        if not session or not session.get("is_initiator"):
            return
        if session.get("state") == "secured":
            return

        public_key_pem = session["key_exchange_instance"].serialize_public_key()
        payload = {
            "type": "key_exchange_init",
            "from": self.client_id,
            "public_key": public_key_pem,
        }
        self.print_ui(f"[*] Sending key exchange initiation to {peer_id}.")
        try:
            if self.udp_sock:
                self.udp_sock.sendto(json.dumps(payload).encode(), session["addr"])
            session["state"] = "key_exchange_sent"
        except Exception as e:
            self.print_ui(f"[!] Failed to send key_exchange_init to {peer_id}: {e}")

    def handle_key_exchange_init(self, peer_id, message, addr):
        session = self.peer_sessions.get(peer_id)
        if not session:
            self.print_ui(
                f"[i] Session for {peer_id} not found on key_exchange_init, creating (responder)."
            )
            self.peer_sessions[peer_id] = {
                "state": "punch_received",
                "addr": addr,
                "key_exchange_instance": KeyExchange(),
                "is_initiator": False,
                "pending_file_offers": {},
                "incoming_file_details": None,
            }
            session = self.peer_sessions[peer_id]

        if session.get("is_initiator"):
            return
        if session.get("state") == "secured":
            return

        peer_public_key_pem = message.get("public_key")
        if not peer_public_key_pem:
            self.print_ui(f"[!] Invalid key_exchange_init from {peer_id}: missing public key.")
            return

        try:
            shared_key = session["key_exchange_instance"].derive_shared_key(
                peer_public_key_pem
            )
            session["shared_key"] = shared_key
            session["state"] = "secured"
            session["addr"] = addr
            self.print_ui(f"[+] Secure channel established with {peer_id}! (Responder)")
            if not self.active_peer:
                self.active_peer = peer_id

            my_public_key_pem = session["key_exchange_instance"].serialize_public_key()
            ack_payload = {
                "type": "key_exchange_ack",
                "from": self.client_id,
                "public_key": my_public_key_pem,
            }
            if self.udp_sock:
                self.udp_sock.sendto(json.dumps(ack_payload).encode(), session["addr"])
        except Exception as e:
            self.print_ui(f"[!] Error in handle_key_exchange_init for {peer_id}: {e}")
            session["state"] = "punch_received"

    def handle_key_exchange_ack(self, peer_id, message, addr):
        session = self.peer_sessions.get(peer_id)
        if not session or not session.get("is_initiator") or "key_exchange_instance" not in session:
            return
        if session.get("state") != "key_exchange_sent":
            return
        if session.get("state") == "secured":
            return

        peer_public_key_pem = message.get("public_key")
        if not peer_public_key_pem:
            self.print_ui(f"[!] Invalid key_exchange_ack from {peer_id}: missing public key.")
            return

        try:
            shared_key = session["key_exchange_instance"].derive_shared_key(
                peer_public_key_pem
            )
            session["shared_key"] = shared_key
            session["state"] = "secured"
            session["addr"] = addr
            self.print_ui(f"[+] Secure channel established with {peer_id}! (Initiator)")
            if not self.active_peer:
                self.active_peer = peer_id
        except Exception as e:
            self.print_ui(f"[!] Error deriving shared key from ack with {peer_id}: {e}")
            session["state"] = "key_exchange_sent"

    def process_direct_message(self, sender_id, message, addr=None):
        msg_type = message.get("type")
        session = self.peer_sessions.get(sender_id)
        if not session or session.get("state") != "secured":
            self.print_ui(
                f"[!] Dropping message type '{msg_type}' from {sender_id}: no secure session."
            )
            return

        if msg_type == "chat":
            self.print_ui(f"<-- [{sender_id}]: {message['content']}")
        elif msg_type == "ping":
            self.print_ui(f"<-- Encrypted ping from {sender_id}. Sending pong.")
            self.send_direct_message(sender_id, {"type": "pong", "from": self.client_id})
        elif msg_type == "pong":
            self.print_ui(f"<-- Encrypted pong received from {sender_id}!")
        elif msg_type == "file_offer":
            self.handle_file_offer(sender_id, message)
        elif msg_type == "file_accept":
            self.handle_file_accept_ack(sender_id, message)
        elif msg_type == "file_reject":
            self.handle_file_reject_ack(sender_id, message)
        elif msg_type == "transfer_starting":
            self.handle_transfer_starting(sender_id, message)
        elif msg_type == "file_chunk":
            self.handle_file_chunk(sender_id, message)
        else:
            self.print_ui(f"[?] Received unknown encrypted message type '{msg_type}' from {sender_id}")

    def handle_file_offer(self, sender_id, offer_msg):
        session = self.peer_sessions.get(sender_id)
        if not session:
            return

        offer_id = offer_msg['offer_id']
        filename = offer_msg['filename']
        filesize = offer_msg['filesize']

        session.setdefault('pending_file_offers', {})[offer_id] = offer_msg

        self.print_ui(f"[i] Incoming file offer from {sender_id} (Offer ID: {offer_id}):")
        self.print_ui(f"    '{filename}' ({filesize} bytes).")
        self.print_ui(f"    To accept, type: /accept {sender_id} {offer_id}")
        self.print_ui(f"    To reject, type: /reject {sender_id} {offer_id}")

    def handle_file_accept_ack(self, sender_id, ack_msg):
        offer_id = ack_msg.get('offer_id')
        original_offer = self.pending_sent_offers.pop(offer_id, None)

        if not original_offer or original_offer['peer_id'] != sender_id:
            self.print_ui(f"[!] Received file_accept for unknown/mismatched offer_id {offer_id} from {sender_id}.")
            return

        filepath = original_offer['filepath']
        filename = original_offer['filename']

        self.print_ui(f"[*] {sender_id} accepted file offer for '{filename}'. Preparing to send...")
        thread = threading.Thread(
            target=self.file_sender_thread,
            args=(sender_id, filepath, filename, original_offer['filesize']),
            daemon=True,
        )
        thread.start()

    def handle_file_reject_ack(self, sender_id, reject_msg):
        offer_id = reject_msg.get('offer_id')
        original_offer = self.pending_sent_offers.pop(offer_id, None)

        if not original_offer or original_offer['peer_id'] != sender_id:
            return

        filename = original_offer['filename']
        self.print_ui(f"[!] {sender_id} rejected the file transfer for '{filename}'.")

    def file_sender_thread(self, target_id, filepath, filename_to_send, filesize):
        try:
            go_signal = {
                "type": "transfer_starting",
                "from": self.client_id,
                "filename": filename_to_send,
                "filesize": filesize,
            }
            self.send_direct_message(target_id, go_signal)
            time.sleep(0.1)

            with open(filepath, 'rb') as f:
                bytes_sent = 0
                while True:
                    if not self.is_connected:
                        self.print_ui(
                            f"\n[!] Disconnected. Aborting file send of '{filename_to_send}'."
                        )
                        break

                    session = self.peer_sessions.get(target_id)
                    if not session or session.get("state") != "secured":
                        self.print_ui(
                            f"\n[!] Lost secure connection to {target_id}. Aborting file send of '{filename_to_send}'."
                        )
                        break

                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    encoded_chunk = base64.b64encode(chunk).decode('ascii')
                    payload = {
                        "type": "file_chunk",
                        "from": self.client_id,
                        "data": encoded_chunk,
                        "filename": filename_to_send,
                    }
                    self.send_direct_message(target_id, payload)

                    bytes_sent += len(chunk)
                    self.print_progress_bar(
                        bytes_sent, filesize, prefix=f"Sending '{filename_to_send}':"
                    )

            if bytes_sent >= filesize:
                self.print_ui(f"[+] File '{filename_to_send}' sent successfully to {target_id}.")
            elif self.is_connected:
                self.print_ui(
                    f"\n[!] File '{filename_to_send}' sending incomplete to {target_id} ({bytes_sent}/{filesize} bytes)."
                )

        except Exception as e:
            self.print_ui(f"[!] Error during file transfer to {target_id}: {e}")

    def handle_transfer_starting(self, sender_id, msg):
        session = self.peer_sessions.get(sender_id)
        if not session:
            return

        filename = msg['filename']
        filesize = msg['filesize']

        accepted_offer_details = session.get('incoming_file_details')
        if not accepted_offer_details or \
           accepted_offer_details['filename'] != filename or \
           accepted_offer_details['filesize'] != filesize or \
           accepted_offer_details['from_peer'] != sender_id:
            self.print_ui(
                f"[!] Mismatch or no prior accept for transfer_starting from {sender_id} for {filename}."
            )
            if 'incoming_file_details' in session:
                del session['incoming_file_details']
            return

        self.print_ui(f"[*] Receiving '{filename}' ({filesize} bytes) from {sender_id}...")
        os.makedirs("received_files", exist_ok=True)
        safe_filename = os.path.basename(filename)
        save_path = os.path.join("received_files", safe_filename)

        session['current_receiving_filepath'] = save_path
        session['current_receiving_filesize'] = filesize
        session['current_receiving_bytes_received'] = 0

        try:
            with open(save_path, 'wb') as f:
                pass
        except Exception as e:
            self.print_ui(f"[!] Error creating file {save_path}: {e}")
            if 'current_receiving_filepath' in session:
                del session['current_receiving_filepath']
            if 'incoming_file_details' in session:
                del session['incoming_file_details']

    def handle_file_chunk(self, sender_id, chunk_msg):
        session = self.peer_sessions.get(sender_id)
        if not session or 'current_receiving_filepath' not in session:
            return

        try:
            filepath = session['current_receiving_filepath']
            total_filesize = session['current_receiving_filesize']
            expected_filename = os.path.basename(filepath)

            if chunk_msg.get('filename') != expected_filename:
                return

            data = base64.b64decode(chunk_msg['data'])
            with open(filepath, 'ab') as f:
                f.write(data)

            session['current_receiving_bytes_received'] += len(data)
            self.print_progress_bar(
                session['current_receiving_bytes_received'],
                total_filesize,
                prefix=f"Receiving '{expected_filename}':",
            )

            if session['current_receiving_bytes_received'] >= total_filesize:
                self.print_ui(
                    f"[+] File '{expected_filename}' received successfully from {sender_id}. Saved to {filepath}"
                )
                del session['current_receiving_filepath']
                del session['current_receiving_filesize']
                del session['current_receiving_bytes_received']
                if 'incoming_file_details' in session and session['incoming_file_details']['filename'] == expected_filename:
                    del session['incoming_file_details']

        except Exception as e:
            self.print_ui(f"[!] Error handling file chunk from {sender_id}: {e}")
            if 'current_receiving_filepath' in session:
                del session['current_receiving_filepath']
            if 'current_receiving_filesize' in session:
                del session['current_receiving_filesize']
            if 'current_receiving_bytes_received' in session:
                del session['current_receiving_bytes_received']
            if 'incoming_file_details' in session:
                del session['incoming_file_details']

    def send_direct_message(self, target_id, payload_dict_app):
        session = self.peer_sessions.get(target_id)
        if not session or session.get("state") != "secured":
            self.print_ui(
                f"[!] No secure connection to {target_id}. Cannot send. State: {session.get('state') if session else 'No session'}"
            )
            return

        try:
            payload_str = json.dumps(payload_dict_app)
            encrypted_payload_b64 = self.crypto_utility.encrypt_layer(
                payload_str, session["shared_key"]
            )

            envelope = {
                "from_id_outer": self.client_id,
                "payload": encrypted_payload_b64,
            }
            if self.udp_sock:
                self.udp_sock.sendto(json.dumps(envelope).encode(), session["addr"])
        except Exception as e:
            self.print_ui(f"[!] Error sending direct message to {target_id}: {e}")

    def main_loop(self):
        if not self.connect_to_relay():
            return

        print("\n--- AltNet Client v22.3 (AES-GCM Secure Tunnel) ---")
        print("  Commands:")
        print("    /scan                    - List online peers.")
        print("    /connect <peer_id>       - Establish secure connection with peer.")
        print("    /say <message>           - Send chat message to active peer.")
        print("    /sendfile <path_to_file> - Offer a file to active peer.")
        print("    /accept <peer_id> <offer_id> - Accept a file offer.")
        print("    /reject <peer_id> <offer_id> - Reject a file offer.")
        print("    /ping                    - Ping active peer (tests secure channel).")
        print("    /active <peer_id>        - Set active peer for commands.")
        print("    /back                    - Deactivate current peer chat.")
        print("    /status                  - Show current connection statuses.")
        print("    /quit                    - Exit.")
        print("  File transfers are saved in 'received_files' directory.")
        print("  Note on Anonymity: Your Client ID provides pseudonymity. All P2P data is encrypted.")
        print(
            "  However, your public IP is known to the relay and your direct peer for connection purposes."
        )
        print("  Using AES-GCM for authenticated encryption.")

        try:
            while self.is_connected:
                prompt_peer_status = ""
                if self.active_peer:
                    session = self.peer_sessions.get(self.active_peer)
                    state = session.get("state", "N/A") if session else "N/A"
                    prompt_peer_status = f" ({self.active_peer} [{state}])"

                current_prompt_text = f"{prompt_peer_status} >> "
                self.last_prompt_for_ui_clear = current_prompt_text

                cmd_input = input(current_prompt_text)
                if not cmd_input:
                    continue

                parts = cmd_input.split(" ", 2)
                command = parts[0]
                arg1 = parts[1] if len(parts) > 1 else None
                arg2 = parts[2] if len(parts) > 2 else None

                if command == "/quit":
                    break
                elif command == "/scan":
                    if self.tcp_sock and self.is_connected:
                        try:
                            self.tcp_sock.sendall(json.dumps({"type": "scan_peers"}).encode())
                        except Exception as e:
                            self.print_ui(f"[!] Error sending scan request: {e}")
                    else:
                        self.print_ui("[!] Not connected to relay.")
                elif command == "/back":
                    if self.active_peer:
                        self.print_ui(f"[*] Deactivated chat with {self.active_peer}.")
                        self.active_peer = None
                    else:
                        self.print_ui("[*] No active peer to go back from.")
                elif command == "/active":
                    if not arg1:
                        self.print_ui("[!] Usage: /active <peer_id>")
                        continue
                    if arg1 not in self.peer_sessions:
                        self.print_ui(f"[!] No session for peer {arg1}. Use /connect first or check ID.")
                        continue
                    self.active_peer = arg1
                    self.print_ui(f"[*] Active peer set to {arg1}.")
                elif command == "/connect":
                    if not arg1:
                        self.print_ui("[!] Usage: /connect <peer_id>")
                        continue
                    if arg1 == self.client_id:
                        self.print_ui("[!] Cannot connect to yourself.")
                        continue

                    session = self.peer_sessions.get(arg1)
                    if session and session.get("state") == "secured":
                        self.print_ui(f"[*] Already securely connected to {arg1}. Setting as active peer.")
                        self.active_peer = arg1
                        continue
                    if session and session.get("state") in [
                        "punching",
                        "punch_acked",
                        "key_exchange_sent",
                        "punch_received",
                        "key_exchanging",
                    ]:
                        self.print_ui(
                            f"[*] Connection process with {arg1} already underway (state: {session.get('state')}). Setting as active."
                        )
                        self.active_peer = arg1
                        continue

                    self.print_ui(f"[*] Requesting to connect with {arg1} via relay...")
                    self.active_peer = arg1
                    if self.tcp_sock and self.is_connected:
                        try:
                            self.tcp_sock.sendall(
                                json.dumps({"type": "initiate_punch", "target": arg1}).encode()
                            )
                        except Exception as e:
                            self.print_ui(f"[!] Error initiating punch: {e}")
                    else:
                        self.print_ui("[!] Not connected to relay. Cannot initiate punch.")

                elif command == "/say":
                    if not self.active_peer:
                        self.print_ui("[!] No active peer. Use /connect or /active first.")
                        continue
                    if not arg1:
                        self.print_ui("[!] Usage: /say <message>")
                        continue
                    full_message = arg1
                    if arg2:
                        full_message += " " + arg2
                    self.send_direct_message(
                        self.active_peer,
                        {"type": "chat", "content": full_message, "from": self.client_id},
                    )

                elif command == "/ping":
                    if not self.active_peer:
                        self.print_ui("[!] No active peer. Use /connect or /active first.")
                        continue
                    self.print_ui(f"--> Sending direct encrypted ping to {self.active_peer}...")
                    self.send_direct_message(
                        self.active_peer, {"type": "ping", "from": self.client_id}
                    )

                elif command == "/sendfile":
                    if not self.active_peer:
                        self.print_ui("[!] No active peer. Use /connect or /active first.")
                        continue
                    if not arg1:
                        self.print_ui("[!] Usage: /sendfile <path_to_file>")
                        continue
                    filepath_input = arg1
                    if arg2:
                        filepath_input += " " + arg2

                    filepath = os.path.expanduser(os.path.expandvars(filepath_input))

                    if not os.path.exists(filepath):
                        self.print_ui(f"[!] File not found: {filepath}")
                        continue
                    if not os.path.isfile(filepath):
                        self.print_ui(f"[!] Path is not a file: {filepath}")
                        continue

                    filename = os.path.basename(filepath)
                    filesize = os.path.getsize(filepath)
                    offer_id = os.urandom(8).hex()

                    self.pending_sent_offers[offer_id] = {
                        "filepath": filepath,
                        "filename": filename,
                        "filesize": filesize,
                        "peer_id": self.active_peer,
                        "timestamp": time.time(),
                    }
                    offer_payload = {
                        "type": "file_offer",
                        "from": self.client_id,
                        "offer_id": offer_id,
                        "filename": filename,
                        "filesize": filesize,
                    }
                    self.print_ui(
                        f"[*] Sending file offer for '{filename}' (Offer ID: {offer_id}) to {self.active_peer}..."
                    )
                    self.send_direct_message(self.active_peer, offer_payload)

                elif command == "/accept":
                    if not arg1 or not arg2:
                        self.print_ui("[!] Usage: /accept <peer_id> <offer_id>")
                        continue
                    peer_id_arg, offer_id_arg = arg1, arg2

                    session = self.peer_sessions.get(peer_id_arg)
                    pending_offers = session.get('pending_file_offers') if session else None
                    if not pending_offers or offer_id_arg not in pending_offers:
                        self.print_ui(
                            f"[!] No pending file offer ID '{offer_id_arg}' from '{peer_id_arg}'."
                        )
                        continue

                    offer_details = pending_offers.pop(offer_id_arg)

                    session['incoming_file_details'] = {
                        "filename": offer_details['filename'],
                        "filesize": offer_details['filesize'],
                        "offer_id": offer_id_arg,
                        "from_peer": peer_id_arg,
                    }

                    response = {
                        "type": "file_accept",
                        "from": self.client_id,
                        "offer_id": offer_id_arg,
                    }
                    self.send_direct_message(peer_id_arg, response)
                    self.print_ui(
                        f"[*] Accepted file '{offer_details['filename']}' from {peer_id_arg}. Notifying sender..."
                    )

                elif command == "/reject":
                    if not arg1 or not arg2:
                        self.print_ui("[!] Usage: /reject <peer_id> <offer_id>")
                        continue
                    peer_id_arg, offer_id_arg = arg1, arg2

                    session = self.peer_sessions.get(peer_id_arg)
                    pending_offers = session.get('pending_file_offers') if session else None
                    if not pending_offers or offer_id_arg not in pending_offers:
                        self.print_ui(
                            f"[!] No pending file offer ID '{offer_id_arg}' from '{peer_id_arg}'."
                        )
                        continue

                    offer_details = pending_offers.pop(offer_id_arg)
                    response = {
                        "type": "file_reject",
                        "from": self.client_id,
                        "offer_id": offer_id_arg,
                        "filename": offer_details['filename'],
                    }
                    self.send_direct_message(peer_id_arg, response)
                    self.print_ui(
                        f"[*] Rejected file offer '{offer_details['filename']}' from {peer_id_arg}."
                    )

                elif command == "/status":
                    self.print_ui("\n--- Connection Status ---")
                    if not self.peer_sessions:
                        self.print_ui("  No active peer sessions.")
                    for pid, pdata in self.peer_sessions.items():
                        state = pdata.get('state', 'N/A')
                        addr = pdata.get('addr', 'N/A')
                        key = "Yes" if pdata.get('shared_key') else "No"
                        init = "Yes" if pdata.get('is_initiator') else "No"
                        self.print_ui(f"  Peer: {pid} (Initiator: {init})")
                        self.print_ui(f"    State: {state}, Addr: {addr}, SharedKey: {key}")
                        if pdata.get('pending_file_offers'):
                            self.print_ui(
                                f"    Pending IN offers: {len(pdata['pending_file_offers'])}"
                            )
                            for off_id, off_data in pdata['pending_file_offers'].items():
                                self.print_ui(
                                    f"      - ID: {off_id}, File: {off_data['filename']}"
                                )

                    if self.pending_sent_offers:
                        self.print_ui(
                            f"  Pending SENT offers: {len(self.pending_sent_offers)}"
                        )
                        for off_id, off_data in self.pending_sent_offers.items():
                            self.print_ui(
                                f"      - ID: {off_id}, File: {off_data['filename']} to {off_data['peer_id']}"
                            )
                    self.print_ui("-------------------------")
                else:
                    self.print_ui(f"[!] Unknown command: {command}")
        except KeyboardInterrupt:
            self.print_ui("\n[*] Quitting...")
        except EOFError:
            self.print_ui("\n[*] Input stream closed. Quitting...")
        finally:
            self.is_connected = False
            if self.tcp_sock:
                try:
                    self.tcp_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.tcp_sock.close()
                self.tcp_sock = None
            if self.udp_sock:
                self.udp_sock.close()
                self.udp_sock = None
            self.print_ui(
                "[*] Disconnected from the network. All threads should terminate."
            )
            time.sleep(0.5)

    def print_ui(self, message):
        with self.ui_lock:
            prompt_to_clear = getattr(self, 'last_prompt_for_ui_clear', ">> ")
            sys.stdout.write('\r' + ' ' * (len(prompt_to_clear) + 100) + '\r')
            print(message)

            prompt_peer_status = ""
            if self.active_peer:
                session = self.peer_sessions.get(self.active_peer)
                state = session.get("state", "N/A") if session else "N/A"
                prompt_peer_status = f" ({self.active_peer} [{state}])"

            current_prompt_text = f"{prompt_peer_status} >> "
            self.last_prompt_for_ui_clear = current_prompt_text
            sys.stdout.write(current_prompt_text)
            sys.stdout.flush()

    def print_progress_bar(self, iteration, total, prefix='', suffix='Complete', length=50, fill='█'):
        with self.ui_lock:
            prompt_to_clear = getattr(self, 'last_prompt_for_ui_clear', ">> ")
            sys.stdout.write('\r' + ' ' * (len(prompt_to_clear) + 100) + '\r')

            percent_str = ("{0:.1f}").format(100 * (iteration / float(total))) if total > 0 else "100.0"
            filled_length = min(length, int(length * iteration // total)) if total > 0 else length
            bar = fill * filled_length + '-' * (length - filled_length)
            progress_msg = f'{prefix} |{bar}| {percent_str}% {suffix}'
            sys.stdout.write(progress_msg)

            if iteration >= total:
                sys.stdout.write('\n')
                sys.stdout.write(self.last_prompt_for_ui_clear)
            sys.stdout.flush()

    def display_scan_results(self, peers):
        self.print_ui("\n--- Online Peers ---")
        if not peers:
            self.print_ui("  (No other peers online)")
        else:
            filtered_peers = [peer_id_scan for peer_id_scan in peers if peer_id_scan != self.client_id]
            if not filtered_peers:
                self.print_ui("  (No other peers online)")
            else:
                for peer_id_scan in filtered_peers:
                    self.print_ui(f"  - {peer_id_scan}")
        self.print_ui("--------------------")

if __name__ == "__main__":
    client = Client()
    client.main_loop()
