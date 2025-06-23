import os, sys; sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
import asyncio
import pytest
import tunnel

async def handle(r, w):
    conn, _ = await tunnel.handshake(r, w, initiator=False)
    msg = await tunnel.read_message(r, conn)
    w.write(tunnel.encrypt_message(conn, msg))
    await w.drain()
    w.close()

@pytest.mark.asyncio
async def test_handshake():
    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    host, port = server.sockets[0].getsockname()
    async with server:
        reader, writer = await asyncio.open_connection(host, port)
        conn, _ = await tunnel.handshake(reader, writer, info={}, initiator=True)
        writer.write(tunnel.encrypt_message(conn, b'ping'))
        await writer.drain()
        reply = await tunnel.read_message(reader, conn)
        assert reply == b'ping'
        writer.close()
