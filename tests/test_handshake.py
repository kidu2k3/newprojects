import os, sys; sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import asyncio
import pytest
import tunnel

async def handle(r, w):
    box, _ = await tunnel.handshake(r, w, initiator=False)
    msg = await tunnel.read_message(r, box)
    w.write(tunnel.encrypt_message(box, msg))
    await w.drain()
    w.close()

@pytest.mark.asyncio
async def test_handshake():
    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    host, port = server.sockets[0].getsockname()
    async with server:
        reader, writer = await asyncio.open_connection(host, port)
        box = await tunnel.handshake(reader, writer, initiator=True, info={})
        writer.write(tunnel.encrypt_message(box, b'ping'))
        await writer.drain()
        reply = await tunnel.read_message(reader, box)
        assert reply == b'ping'
        writer.close()
