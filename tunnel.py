"""Utility functions for establishing encrypted tunnels."""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import secrets
import struct
import time
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from noise.connection import NoiseConnection, Keypair
from noise.exceptions import NoiseInvalidMessage

# Configure main logger
logger = logging.getLogger(__name__)

# Configure security event logger
security_logger = logging.getLogger('security_events')
security_logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(event_type)s - %(message)s')

# Security event types
class SecurityEventType(Enum):
    HANDSHAKE_FAILED = "HANDSHAKE_FAILED"
    ROTATION_FAILED = "ROTATION_FAILED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    AUTH_FAILED = "AUTH_FAILED"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    HANDSHAKE_SUCCESS = "HANDSHAKE_SUCCESS"
    ROTATION_SUCCESS = "ROTATION_SUCCESS"

# Constants for security parameters
MAX_MESSAGE_SIZE = 65535  # Maximum size of encrypted messages
HANDSHAKE_TIMEOUT = 30.0  # Default handshake timeout in seconds
KEY_ROTATION_INTERVAL = 3600  # Rotate session keys every hour
REPLAY_WINDOW = 300  # 5 minute replay protection window
MESSAGES_BEFORE_ROTATION = 100  # Number of messages before key rotation
ROTATION_TIMEOUT = 5.0  # Key rotation timeout in seconds

def log_security_event(event_type: SecurityEventType, details: str, extra: Dict[str, Any] = None):
    """Log a security event with contextual details."""
    extra = extra or {}
    extra['event_type'] = event_type.value
    security_logger.info(
        details,
        extra=extra
    )

class HandshakeError(Exception):
    """Raised when handshake fails."""
    pass

class ReplayError(Exception):
    """Raised when a replay attack is detected."""
    pass

class RotationError(Exception):
    """Raised when key rotation fails."""
    pass

class SecurityContext:
    """Maintains security state for connection."""
    def __init__(self, 
                 initial_noise: NoiseConnection,
                 static_private: bytes,
                 static_public: bytes,
                 peer_static_public: bytes,
                 is_initiator: bool):
        self.seen_nonces = {}  # timestamp -> set of nonces
        self.last_rotation = time.time()
        self.noise = initial_noise
        self.message_counter = 0
        
        # Store key material for rotations
        self._static_private = static_private
        self._static_public = static_public
        self._peer_static_public = peer_static_public
        self._is_initiator = is_initiator
        self._rotating = False
        self._rotation_time = None  # When we started rotating
    
    async def rotate_keys(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> NoiseConnection:
        """Perform key rotation with peer."""
        if self._rotating:
            log_security_event(
                SecurityEventType.ROTATION_FAILED,
                "Key rotation already in progress",
                {"is_initiator": self._is_initiator}
            )
            raise RotationError("Key rotation already in progress")
        
        self._rotating = True
        logger.debug("Starting key rotation")
        
        try:
            # Create new handshake state
            new_noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
            
            # Initialize new handshake with fresh ephemeral keys
            if self._is_initiator:
                new_noise.set_as_initiator()
            else:
                new_noise.set_as_responder()
                
            # Set keys and start handshake
            new_noise.set_keypair_from_private_bytes(Keypair.STATIC, self._static_private)
            new_noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, self._peer_static_public)
            new_noise.set_prologue(b"key_rotation")  # Add context
            new_noise.start_handshake()
            
            # Perform rotation handshake
            if self._is_initiator:
                # -> Rotation request with a random nonce
                nonce = secrets.token_bytes(32)
                writer.write(struct.pack("!I4s32s", 36, b"ROT:", nonce))
                await writer.drain()
                
                # <- Rotation acknowledgment with nonce
                size_bytes = await asyncio.wait_for(reader.readexactly(4), ROTATION_TIMEOUT)
                ack_len = struct.unpack("!I", size_bytes)[0]
                if ack_len != 36:
                    log_security_event(
                        SecurityEventType.ROTATION_FAILED,
                        f"Invalid ACK size during rotation",
                        {"expected": 36, "received": ack_len}
                    )
                    raise RotationError(f"Invalid ACK size: {ack_len}")
                ack = await asyncio.wait_for(reader.readexactly(36), ROTATION_TIMEOUT)
                if not ack.startswith(b"ACK:"):
                    log_security_event(
                        SecurityEventType.ROTATION_FAILED,
                        "Invalid rotation response header"
                    )
                    raise RotationError("Invalid rotation response header")
                resp_nonce = ack[4:]  # Skip ACK: prefix
                if resp_nonce != nonce:
                    log_security_event(
                        SecurityEventType.ROTATION_FAILED,
                        "Nonce mismatch in rotation response"
                    )
                    raise RotationError("Nonce mismatch in rotation response")
                
                try:
                    # -> e, es, s, ss (IK pattern - initiator sends first)
                    rotation_payload = {"rotation": True, "timestamp": time.time()}
                    payload = json.dumps(rotation_payload).encode()
                    msg1 = new_noise.write_message(payload)
                    msg = b"HSH:" + msg1
                    writer.write(struct.pack("!I", len(msg)) + msg)
                    await writer.drain()
                    logger.debug("Sent e, es, s, ss")
                    
                    # <- e, ee, se (read directly, not through read_message)
                    len_bytes = await asyncio.wait_for(reader.readexactly(4), ROTATION_TIMEOUT)
                    resp_len = struct.unpack("!I", len_bytes)[0]
                    if resp_len > MAX_MESSAGE_SIZE:
                        log_security_event(
                            SecurityEventType.ROTATION_FAILED,
                            "Response message too large during rotation",
                            {"size": resp_len}
                        )
                        raise RotationError(f"Response message too large: {resp_len}")
                    resp = await asyncio.wait_for(reader.readexactly(resp_len), ROTATION_TIMEOUT)
                    
                    if not resp.startswith(b"HSH:"):
                        log_security_event(
                            SecurityEventType.ROTATION_FAILED,
                            "Invalid response prefix during rotation"
                        )
                        raise RotationError("Invalid response prefix")
                    resp_data = resp[4:]  # Skip HSH: prefix
                    peer_payload = new_noise.read_message(resp_data)
                    peer_data = json.loads(peer_payload.decode())
                    logger.debug("Processed e, ee, se - handshake complete")
                    
                except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
                    log_security_event(
                        SecurityEventType.CONNECTION_ERROR,
                        f"Connection error during rotation handshake: {e}"
                    )
                    raise RotationError(f"Connection error during handshake: {e}") from e
                except Exception as e:
                    log_security_event(
                        SecurityEventType.ROTATION_FAILED,
                        f"Failed to process handshake data: {e}"
                    )
                    raise RotationError(f"Failed to process handshake data: {e}") from e
                
            else:
                try:
                    # <- Rotation request with nonce
                    header_size = await asyncio.wait_for(reader.readexactly(4), ROTATION_TIMEOUT)
                    size = struct.unpack("!I", header_size)[0]
                    if size != 36:
                        log_security_event(
                            SecurityEventType.ROTATION_FAILED,
                            f"Invalid request size during rotation",
                            {"expected": 36, "received": size}
                        )
                        raise RotationError(f"Invalid request size: {size}")
                    
                    msg = await asyncio.wait_for(reader.readexactly(36), ROTATION_TIMEOUT)
                    if not msg.startswith(b"ROT:"):
                        log_security_event(
                            SecurityEventType.ROTATION_FAILED,
                            "Invalid rotation request header"
                        )
                        raise RotationError("Invalid rotation request header")
                    nonce = msg[4:]  # Skip ROT: prefix
                    
                    # -> Rotation acknowledgment
                    ack_msg = b"ACK:" + nonce
                    writer.write(struct.pack("!I", len(ack_msg)) + ack_msg)
                    await writer.drain()
                    logger.debug("Sent rotation acknowledgment")
                    
                    # <- e, es, s, ss (from initiator - read directly)
                    len_bytes = await asyncio.wait_for(reader.readexactly(4), ROTATION_TIMEOUT)
                    msg_len = struct.unpack("!I", len_bytes)[0]
                    if msg_len > MAX_MESSAGE_SIZE:
                        log_security_event(
                            SecurityEventType.ROTATION_FAILED,
                            "Handshake message too large during rotation",
                            {"size": msg_len}
                        )
                        raise RotationError(f"Handshake message too large: {msg_len}")
                    msg1 = await asyncio.wait_for(reader.readexactly(msg_len), ROTATION_TIMEOUT)
                    
                    if not msg1.startswith(b"HSH:"):
                        log_security_event(
                            SecurityEventType.ROTATION_FAILED,
                            "Invalid message prefix during rotation"
                        )
                        raise RotationError("Invalid message prefix")
                    
                    # Process initiator's message and generate response
                    msg_data = msg1[4:]  # Skip HSH: prefix
                    peer_payload = new_noise.read_message(msg_data)
                    peer_data = json.loads(peer_payload.decode())
                    logger.debug("Processed e, es, s, ss")
                    
                    # -> e, ee, se
                    rotation_payload = {"rotation": True, "timestamp": time.time()}
                    payload = json.dumps(rotation_payload).encode()
                    resp = new_noise.write_message(payload)
                    resp_msg = b"HSH:" + resp
                    writer.write(struct.pack("!I", len(resp_msg)) + resp_msg)
                    await writer.drain()
                    logger.debug("Sent e, ee, se - handshake complete")
                    
                except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
                    log_security_event(
                        SecurityEventType.CONNECTION_ERROR,
                        f"Connection error during rotation handshake: {e}"
                    )
                    raise RotationError(f"Connection error during handshake: {e}") from e
                except Exception as e:
                    log_security_event(
                        SecurityEventType.ROTATION_FAILED,
                        f"Failed to process handshake message: {e}"
                    )
                    raise RotationError(f"Failed to process handshake message: {e}") from e
            
            log_security_event(
                SecurityEventType.ROTATION_SUCCESS,
                "Key rotation completed successfully",
                {"is_initiator": self._is_initiator}
            )
            logger.debug("Key rotation complete")
            return new_noise
        
        except Exception as e:
            log_security_event(
                SecurityEventType.ROTATION_FAILED,
                f"Key rotation failed: {e}",
                {"is_initiator": self._is_initiator}
            )
            logger.error("Key rotation failed: %s", e)
            raise RotationError(f"Key rotation failed: {e}")
        
        finally:
            self._rotating = False
    
    async def rotate_if_needed(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """Check if we need to rotate keys and do so if needed."""
        now = time.time()
        self.message_counter += 1
        
        # Check if rotation is needed
        if not (now - self.last_rotation >= KEY_ROTATION_INTERVAL or 
                self.message_counter >= MESSAGES_BEFORE_ROTATION):
            return False
            
        # Only initiator triggers rotation
        if not self._is_initiator:
            return False
            
        # Rate limit rotation attempts
        if self._rotation_time and now - self._rotation_time < ROTATION_TIMEOUT:
            return False
            
        # Perform key rotation
        try:
            self._rotation_time = time.time()
            self.noise = await self.rotate_keys(reader, writer)
            self.last_rotation = time.time()
            self.message_counter = 0
            self._rotation_time = None
            return True
        except RotationError as e:
            # Re-raise specific rotation errors
            raise
        except Exception as e:
            # Wrap unexpected errors in RotationError
            log_security_event(
                SecurityEventType.ROTATION_FAILED,
                f"Unexpected error during key rotation: {e}"
            )
            raise RotationError(f"Unexpected error during key rotation: {e}") from e
    
    def clean_replay_window(self):
        """Remove timestamps outside replay window."""
        cutoff = time.time() - REPLAY_WINDOW
        self.seen_nonces = {
            ts: nonces for ts, nonces in self.seen_nonces.items()
            if ts > cutoff
        }
    
    def check_replay(self, timestamp: float, nonce: bytes) -> bool:
        """Check if nonce was seen before in replay window."""
        self.clean_replay_window()
        
        if timestamp < time.time() - REPLAY_WINDOW:
            log_security_event(
                SecurityEventType.REPLAY_DETECTED,
                "Message timestamp too old",
                {"timestamp": timestamp}
            )
            return False  # Too old
            
        if timestamp > time.time() + 60:
            log_security_event(
                SecurityEventType.REPLAY_DETECTED,
                "Message timestamp too far in future",
                {"timestamp": timestamp}
            )
            return False  # Too far in future
            
        if timestamp not in self.seen_nonces:
            self.seen_nonces[timestamp] = set()
            
        if nonce in self.seen_nonces[timestamp]:
            log_security_event(
                SecurityEventType.REPLAY_DETECTED,
                "Duplicate nonce detected",
                {"timestamp": timestamp}
            )
            return False  # Replayed nonce
            
        self.seen_nonces[timestamp].add(nonce)
        return True

async def handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    static_private: bytes,
    static_public: bytes,
    peer_static_public: bytes,
    info: Dict[str, Any] | None = None,
    *,
    initiator: bool = True,
    timeout: float = HANDSHAKE_TIMEOUT,
) -> Tuple[SecurityContext, Dict[str, Any]]:
    """Perform an authenticated Noise_IK handshake."""
    # Initialize Noise with static key authentication
    noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
    
    if initiator:
        noise.set_as_initiator()
    else:
        noise.set_as_responder()
        
    # Set static keys
    noise.set_keypair_from_private_bytes(Keypair.STATIC, static_private)
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, peer_static_public)
    
    noise.start_handshake()

    # Add timestamp and nonce to prevent replays
    handshake_data = {
        "timestamp": time.time(),
        "nonce": secrets.token_bytes(32).hex(),
        "info": info or {}
    }
    payload = json.dumps(handshake_data).encode()

    try:
        if initiator:
            # -> e, es, s, ss
            msg = noise.write_message(payload)
            writer.write(struct.pack("!I", len(msg)) + msg)
            await writer.drain()

            # <- e, ee, se
            len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout)
            length = struct.unpack("!I", len_bytes)[0]
            if length > MAX_MESSAGE_SIZE:
                log_security_event(
                    SecurityEventType.HANDSHAKE_FAILED,
                    f"Message too large during handshake",
                    {"size": length}
                )
                raise HandshakeError(f"Message too large: {length}")
            resp = await asyncio.wait_for(reader.readexactly(length), timeout)
            peer_payload = noise.read_message(resp)
            
        else:
            # <- e, es, s, ss
            len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout) 
            length = struct.unpack("!I", len_bytes)[0]
            if length > MAX_MESSAGE_SIZE:
                log_security_event(
                    SecurityEventType.HANDSHAKE_FAILED,
                    f"Message too large during handshake",
                    {"size": length}
                )
                raise HandshakeError(f"Message too large: {length}")
            data = await asyncio.wait_for(reader.readexactly(length), timeout)
            peer_payload = noise.read_message(data)

            # -> e, ee, se
            msg = noise.write_message(payload)
            writer.write(struct.pack("!I", len(msg)) + msg)
            await writer.drain()

        # Validate peer handshake data
        peer_data = json.loads(peer_payload.decode())
        peer_ts = peer_data.get("timestamp")
        peer_nonce = bytes.fromhex(peer_data.get("nonce"))
        
        context = SecurityContext(
            noise,
            static_private=static_private,
            static_public=static_public,
            peer_static_public=peer_static_public,
            is_initiator=initiator
        )
        if not context.check_replay(peer_ts, peer_nonce):
            log_security_event(
                SecurityEventType.REPLAY_DETECTED,
                "Replay attempt during handshake",
                {"timestamp": peer_ts}
            )
            raise ReplayError("Detected replay attempt")
            
        peer_info = peer_data.get("info", {})
        log_security_event(
            SecurityEventType.HANDSHAKE_SUCCESS,
            "Authenticated handshake completed successfully",
            {
                "is_initiator": initiator,
                "peer_info": peer_info
            }
        )
        logger.debug("Authenticated handshake complete with info %s", peer_info)
        
        return context, peer_info
        
    except (asyncio.TimeoutError, json.JSONDecodeError, ValueError) as e:
        log_security_event(
            SecurityEventType.HANDSHAKE_FAILED,
            f"Handshake failed: {str(e)}",
            {"is_initiator": initiator}
        )
        raise HandshakeError(f"Handshake failed: {str(e)}")

async def encrypt_message(context: SecurityContext, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes) -> bytes:
    """Encrypt a payload using the Noise session."""
    if await context.rotate_if_needed(reader, writer):
        logger.debug("Rotated session keys")
        
    # Add timestamp and nonce for replay protection
    msg_data = {
        "timestamp": time.time(),
        "nonce": secrets.token_bytes(32).hex(),
        "payload": data.hex()
    }
    msg = json.dumps(msg_data).encode()
    
    enc = context.noise.encrypt(msg)
    logger.debug("Encrypting %d bytes", len(data))
    return struct.pack('!I', len(enc)) + enc

async def read_message(reader: asyncio.StreamReader, context: SecurityContext, writer: asyncio.StreamWriter = None) -> Optional[bytes]:
    """Decrypt and validate an incoming message."""
    try:
        len_bytes = await reader.read(4)
        if not len_bytes:  # Connection closed
            log_security_event(
                SecurityEventType.CONNECTION_ERROR,
                "Connection closed by peer"
            )
            raise ConnectionError("Connection closed by peer")
            
        size_prefix = struct.unpack('!I', len_bytes)[0]
        if size_prefix > MAX_MESSAGE_SIZE:
            log_security_event(
                SecurityEventType.AUTH_FAILED,
                f"Message too large",
                {"size": size_prefix}
            )
            raise ValueError(f"Message too large: {size_prefix}")
            
        # Read and process the message
        msg = await reader.readexactly(size_prefix)
        
        # Handle protocol messages
        if msg.startswith(b"ROT:") and size_prefix == 36:
            # Handle rotation request
            if writer is not None and not context._is_initiator:
                _, _, nonce = struct.unpack("!I4s32s", len_bytes + msg)
                ack_msg = b"ACK:" + nonce
                writer.write(struct.pack("!I", len(ack_msg)) + ack_msg)
                await writer.drain()
                logger.debug("Sent rotation acknowledgment")
                # Prepare for incoming key rotation
                context._rotation_time = time.time()
            return None
            
        if msg.startswith(b"ACK:") and size_prefix == 36:
            # Let rotate_keys handle ACK
            return None
            
        if msg.startswith(b"HSH:"):
            # Handle key rotation handshake message
            if writer is not None and not context._is_initiator and context._rotation_time:
                # This is part of key rotation - handle it directly
                try:
                    # Create new handshake state for rotation
                    new_noise = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_BLAKE2s")
                    new_noise.set_as_responder()
                    new_noise.set_keypair_from_private_bytes(Keypair.STATIC, context._static_private)
                    new_noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, context._peer_static_public)
                    new_noise.set_prologue(b"key_rotation")
                    new_noise.start_handshake()
                    
                    # Process initiator's message and generate response
                    msg_data = msg[4:]  # Skip HSH: prefix
                    peer_payload = new_noise.read_message(msg_data)
                    peer_data = json.loads(peer_payload.decode())
                    logger.debug("Server processed e, es, s, ss")
                    
                    # -> e, ee, se
                    rotation_payload = {"rotation": True, "timestamp": time.time()}
                    payload = json.dumps(rotation_payload).encode()
                    resp = new_noise.write_message(payload)
                    resp_msg = b"HSH:" + resp
                    writer.write(struct.pack("!I", len(resp_msg)) + resp_msg)
                    await writer.drain()
                    logger.debug("Server sent e, ee, se - rotation complete")
                    
                    # Update context with new noise connection
                    context.noise = new_noise
                    context.last_rotation = time.time()
                    context.message_counter = 0
                    context._rotation_time = None
                    
                    log_security_event(
                        SecurityEventType.ROTATION_SUCCESS,
                        "Server completed key rotation",
                        {"is_initiator": False}
                    )
                    
                except Exception as e:
                    log_security_event(
                        SecurityEventType.ROTATION_FAILED,
                        f"Server key rotation failed: {e}"
                    )
                    logger.error("Server key rotation failed: %s", e)
                    context._rotation_time = None
                return None
            else:
                # Return full message for rotate_keys to handle on initiator side
                return msg
            
        # Normal encrypted message
        logger.debug("Decrypting %d bytes", size_prefix)
        enc = msg
        if not enc:
            log_security_event(
                SecurityEventType.CONNECTION_ERROR,
                "Connection closed by peer during message read"
            )
            raise ConnectionError("Connection closed by peer")
            
        try:
            dec = context.noise.decrypt(enc)
        except NoiseInvalidMessage:
            log_security_event(
                SecurityEventType.AUTH_FAILED,
                "Invalid message authentication - possible replay attack"
            )
            logger.warning("Invalid message detected - likely replay attack")
            raise ReplayError("Invalid message authentication - possible replay attack")
            
        msg_data = json.loads(dec.decode())
        
        # Validate timestamp and nonce
        ts = msg_data.get("timestamp")
        nonce = bytes.fromhex(msg_data.get("nonce"))
        
        if not context.check_replay(ts, nonce):
            log_security_event(
                SecurityEventType.REPLAY_DETECTED,
                "Replay attempt detected",
                {"timestamp": ts}
            )
            raise ReplayError("Detected replay attempt")
            
        return bytes.fromhex(msg_data["payload"])
        
    except (struct.error, json.JSONDecodeError, ValueError, KeyError) as e:
        log_security_event(
            SecurityEventType.AUTH_FAILED,
            f"Failed to decrypt message: {e}"
        )
        logger.error("Failed to decrypt message: %s", e)
        return None
    except ConnectionError:
        raise  # Re-raise connection errors to handle disconnection
    except Exception as e:
        log_security_event(
            SecurityEventType.AUTH_FAILED,
            f"Unexpected error in read_message: {e}"
        )
        logger.error("Unexpected error in read_message: %s", e)
        return None
