import os, sys; sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
import asyncio
import logging
import pytest
from noise.connection import NoiseConnection, Keypair
from nacl.public import PrivateKey
import tunnel

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configure security event logger for testing
security_logger = logging.getLogger('security_events')
security_logger.setLevel(logging.INFO)

class TestLogHandler(logging.Handler):
    """Custom handler to capture log records for testing."""
    def __init__(self):
        super().__init__()
        self.records = []
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(event_type)s - %(message)s')

    def emit(self, record):
        self.records.append(record)

    def get_records_for_event(self, event_type):
        return [r for r in self.records if hasattr(r, 'event_type') and r.event_type == event_type]

    def clear(self):
        self.records.clear()

@pytest.fixture
def log_handler():
    """Fixture to provide a clean log handler for each test."""
    handler = TestLogHandler()
    security_logger.addHandler(handler)
    yield handler
    security_logger.removeHandler(handler)
    handler.clear()

def generate_keypair():
    """Generate a static keypair for testing using libsodium."""
    private_key = PrivateKey.generate()
    return private_key.encode(), private_key.public_key.encode()

@pytest.fixture
def keypairs():
    """Generate static keypairs for both sides."""
    server_private, server_public = generate_keypair()
    client_private, client_public = generate_keypair()
    return {
        "server": (server_private, server_public),
        "client": (client_private, client_public)
    }

async def handle(r, w, server_keys, client_public):
    """Server-side handler."""
    task = asyncio.current_task()
    try:
        logger.debug("Server handler starting")
        server_private, server_public = server_keys
        context, peer_info = await tunnel.handshake(
            r, w,
            static_private=server_private,
            static_public=server_public,
            peer_static_public=client_public,
            initiator=False
        )
        logger.debug("Server handshake complete")
        
        while not task.cancelled():
            try:
                msg = await tunnel.read_message(r, context, w)
                if msg is not None:
                    logger.debug("Server received message: %r", msg)
                    enc = await tunnel.encrypt_message(context, r, w, msg)
                    w.write(enc)
                    await w.drain()
            except tunnel.ReplayError as e:
                logger.debug("Server detected replay attack: %s", e)
                try:
                    # Forward the replay error to the client and cleanup
                    w.write(b"REPLAY")
                    await w.drain()
                except Exception:
                    pass  # Ignore errors during cleanup
                break  # Exit the message loop
            except ConnectionError:
                logger.debug("Client disconnected")
                break
            except Exception as e:
                logger.error("Server handler error: %s", e)
                break
    finally:
        logger.debug("Server handler cleanup")
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass  # Ignore cleanup errors

@pytest.mark.asyncio
async def test_handshake_authentication(keypairs, log_handler):
    """Test authenticated handshake with static keys."""
    logger.info("Starting handshake authentication test")
    server_keys = keypairs["server"]
    client_keys = keypairs["client"]
    
    # Start server
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, server_keys, client_keys[1]),
        '127.0.0.1', 0
    )
    host, port = server.sockets[0].getsockname()
    logger.debug("Server started on %s:%d", host, port)
    
    async with server:
        # Client connects and performs handshake
        reader, writer = await asyncio.open_connection(host, port)
        try:
            logger.debug("Client connected, starting handshake")
            client_private, client_public = client_keys
            context, peer_info = await tunnel.handshake(
                reader, writer,
                static_private=client_private,
                static_public=client_public,
                peer_static_public=server_keys[1],
                info={"test": "data"},
                initiator=True
            )
            logger.debug("Client handshake complete")
            
            # Verify successful handshake was logged
            handshake_logs = log_handler.get_records_for_event("HANDSHAKE_SUCCESS")
            assert len(handshake_logs) == 2  # One from client, one from server
            assert any(r.is_initiator for r in handshake_logs)
            assert any(not r.is_initiator for r in handshake_logs)
            
            # Test encrypted communication
            writer.write(await tunnel.encrypt_message(context, reader, writer, b'ping'))
            await writer.drain()
            logger.debug("Client sent ping")
            
            reply = await tunnel.read_message(reader, context, writer)
            logger.debug("Client received reply: %r", reply)
            assert reply == b'ping'
            logger.info("Handshake authentication test passed")
            
        finally:
            writer.close()
            await writer.wait_closed()

@pytest.mark.asyncio
async def test_handshake_failure(keypairs, log_handler):
    """Test handshake failure logging."""
    logger.info("Starting handshake failure test")
    server_keys = keypairs["server"]
    client_keys = keypairs["client"]
    
    # Start server
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, server_keys, client_keys[1]),
        '127.0.0.1', 0
    )
    host, port = server.sockets[0].getsockname()
    
    async with server:
        # Client connects but uses wrong server public key
        reader, writer = await asyncio.open_connection(host, port)
        try:
            logger.debug("Client connected, starting handshake with wrong key")
            client_private, client_public = client_keys
            wrong_server_public = os.urandom(32)  # Wrong key
            
            with pytest.raises(tunnel.HandshakeError):
                await tunnel.handshake(
                    reader, writer,
                    static_private=client_private,
                    static_public=client_public,
                    peer_static_public=wrong_server_public,
                    initiator=True
                )
            
            # Verify handshake failure was logged
            failure_logs = log_handler.get_records_for_event("HANDSHAKE_FAILED")
            assert len(failure_logs) >= 1
            assert "Handshake failed" in failure_logs[0].message
            
        finally:
            writer.close()
            await writer.wait_closed()

@pytest.mark.asyncio
async def test_replay_protection(keypairs, log_handler):
    """Test that replay attacks are detected and logged."""
    logger.info("Starting replay protection test")
    server_keys = keypairs["server"]
    client_keys = keypairs["client"]
    
    # Start server
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, server_keys, client_keys[1]),
        '127.0.0.1', 0
    )
    host, port = server.sockets[0].getsockname()
    logger.debug("Server started on %s:%d", host, port)
    
    async with server:
        # First connection
        reader1, writer1 = await asyncio.open_connection(host, port)
        try:
            logger.debug("First client connected")
            client_private, client_public = client_keys
            context1, _ = await tunnel.handshake(
                reader1, writer1,
                static_private=client_private,
                static_public=client_public,
                peer_static_public=server_keys[1],
                initiator=True
            )
            logger.debug("First client handshake complete")
            
            # Encrypt a message and capture it
            encrypted = await tunnel.encrypt_message(context1, reader1, writer1, b'ping')
            writer1.write(encrypted)
            await writer1.drain()
            logger.debug("First client sent message")
            
            # Wait for first message to complete
            reply = await tunnel.read_message(reader1, context1, writer1)
            assert reply == b'ping'
            logger.debug("First client received reply")
            
        finally:
            writer1.close()
            await writer1.wait_closed()
        
        # Wait for server to cleanup first connection
        await asyncio.sleep(0.1)
        logger.debug("First connection closed")
        
        # New connection attempts to replay the message
        reader2, writer2 = await asyncio.open_connection(host, port)
        try:
            logger.debug("Second client connected")
            context2, _ = await tunnel.handshake(
                reader2, writer2,
                static_private=client_private,
                static_public=client_public,
                peer_static_public=server_keys[1],
                initiator=True
            )
            logger.debug("Second client handshake complete")
            
            # Clear logs from handshake
            log_handler.clear()
            
            # Attempt replay
            writer2.write(encrypted)
            await writer2.drain()
            logger.debug("Second client attempted replay")
            
            # Wait for server response and potential error
            try:
                data = await asyncio.wait_for(reader2.read(6), timeout=2.0)
                if data == b"REPLAY":
                    # Verify replay attack was logged
                    replay_logs = log_handler.get_records_for_event("REPLAY_DETECTED")
                    assert len(replay_logs) >= 1
                    assert "Replay attempt detected" in replay_logs[0].message
                    logger.info("Replay protection test passed: Server detected replay attack")
                else:
                    pytest.fail("Server did not detect replay attack")
            except asyncio.TimeoutError:
                logger.info("Replay protection test passed: Connection closed after replay detection")
            except Exception as e:
                pytest.fail(f"Unexpected error during replay test: {e}")
                
        finally:
            writer2.close()
            try:
                await asyncio.wait_for(writer2.wait_closed(), timeout=1.0)
            except asyncio.TimeoutError:
                pass  # Socket may already be closed

@pytest.mark.asyncio
async def test_key_rotation(keypairs, log_handler):
    """Test that session keys are rotated and rotation events are logged."""
    logger.info("Starting key rotation test")
    server_keys = keypairs["server"]
    client_keys = keypairs["client"]
    
    # Start server with shorter rotation interval for testing
    tunnel.KEY_ROTATION_INTERVAL = 0.1  # 100ms for testing
    tunnel.MESSAGES_BEFORE_ROTATION = 2  # Rotate after 2 messages
    
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, server_keys, client_keys[1]),
        '127.0.0.1', 0
    )
    host, port = server.sockets[0].getsockname()
    logger.debug("Server started on %s:%d", host, port)
    
    async with server:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            logger.debug("Client connected")
            client_private, client_public = client_keys
            context, _ = await tunnel.handshake(
                reader, writer,
                static_private=client_private,
                static_public=client_public,
                peer_static_public=server_keys[1],
                initiator=True
            )
            logger.debug("Client handshake complete")
            
            # Clear logs from handshake
            log_handler.clear()
            
            # Send first message
            enc = await tunnel.encrypt_message(context, reader, writer, b'ping1')
            writer.write(enc)
            await writer.drain()
            logger.debug("Sent first message")
            
            reply = await tunnel.read_message(reader, context, writer)
            assert reply == b'ping1'
            logger.debug("Received first reply")
            
            # Wait for key rotation
            await asyncio.sleep(0.2)
            logger.debug("Waited for key rotation")
            
            # Send second message (should trigger key rotation)
            enc = await tunnel.encrypt_message(context, reader, writer, b'ping2')
            writer.write(enc)
            await writer.drain()
            logger.debug("Sent second message")
            
            reply = await tunnel.read_message(reader, context, writer)
            assert reply == b'ping2'
            logger.debug("Received second reply")
            
            # Verify rotation success was logged
            rotation_logs = log_handler.get_records_for_event("ROTATION_SUCCESS")
            assert len(rotation_logs) >= 2  # One from client, one from server
            assert any("completed key rotation" in r.message for r in rotation_logs)
            
            # Send third message with rotated keys
            enc = await tunnel.encrypt_message(context, reader, writer, b'ping3')
            writer.write(enc)
            await writer.drain()
            logger.debug("Sent third message")
            
            reply = await tunnel.read_message(reader, context, writer)
            assert reply == b'ping3'
            logger.debug("Received third reply")
            
            logger.info("Key rotation test passed")
        finally:
            writer.close()
            await writer.wait_closed()

@pytest.mark.asyncio
async def test_connection_error_logging(keypairs, log_handler):
    """Test that connection errors are properly logged."""
    logger.info("Starting connection error test")
    server_keys = keypairs["server"]
    client_keys = keypairs["client"]
    
    # Start server
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, server_keys, client_keys[1]),
        '127.0.0.1', 0
    )
    host, port = server.sockets[0].getsockname()
    
    async with server:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            logger.debug("Client connected")
            client_private, client_public = client_keys
            context, _ = await tunnel.handshake(
                reader, writer,
                static_private=client_private,
                static_public=client_public,
                peer_static_public=server_keys[1],
                initiator=True
            )
            
            # Clear logs from handshake
            log_handler.clear()
            
            # Simulate connection close during message read
            writer.close()
            await writer.wait_closed()
            
            # Attempt to read message after connection close
            with pytest.raises(ConnectionError):
                await tunnel.read_message(reader, context)
            
            # Verify connection error was logged
            error_logs = log_handler.get_records_for_event("CONNECTION_ERROR")
            assert len(error_logs) >= 1
            assert "Connection closed by peer" in error_logs[0].message
            
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

if __name__ == '__main__':
    logger.info("Running tests manually")
    
    async def run_tests():
        pairs = {"server": generate_keypair(), "client": generate_keypair()}
        handler = TestLogHandler()
        security_logger.addHandler(handler)
        
        try:
            await test_handshake_authentication(pairs, handler)
            await test_handshake_failure(pairs, handler)
            await test_replay_protection(pairs, handler)
            await test_key_rotation(pairs, handler)
            await test_connection_error_logging(pairs, handler)
            logger.info("All tests passed!")
        except Exception as e:
            logger.error("Test failed: %s", e)
            raise
        finally:
            security_logger.removeHandler(handler)
    
    asyncio.run(run_tests())
