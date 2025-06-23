import os
import sys
import asyncio
import threading
import time
import json

import aiohttp
import pytest

# Ensure modules are importable
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from dashboard.dashboard import app as dashboard_app
from relay.relay import run_server
from client import client as client_module
from client.client import fetch_relays, open_chain, ping_relays
import client.dashboard_app as client_dash
from tunnel import encrypt_message, read_message

from werkzeug.serving import make_server

def run_flask_app(app, port):
    server = make_server('127.0.0.1', port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # give server time to start
    time.sleep(0.1)
    return server


async def start_relay(host, port, dashboard_url):
    async def dummy(active):
        pass
    task = asyncio.create_task(run_server(host, port, dummy, dashboard_url))
    # allow server to start
    await asyncio.sleep(0.1)
    return task


async def start_echo_server(host='127.0.0.1', port=0):
    async def handler(r, w):
        while True:
            data = await r.read(4096)
            if not data:
                break
            w.write(data)
            await w.drain()
        w.close()
    server = await asyncio.start_server(handler, host, port)
    await asyncio.sleep(0.05)
    return server


@pytest.mark.asyncio
async def test_connectivity_and_dashboard():
    dashboard_port = 5001
    dash_server = run_flask_app(dashboard_app, dashboard_port)

    # start relay
    relay_port = 9100
    relay_task = await start_relay('127.0.0.1', relay_port, f'http://127.0.0.1:{dashboard_port}')

    # register relay with dashboard
    async with aiohttp.ClientSession() as session:
        await session.post(f'http://127.0.0.1:{dashboard_port}/register', json={'host': '127.0.0.1', 'port': relay_port})

    # patch relay list URL used by client modules
    client_module.RELAY_LIST_URL = f'http://127.0.0.1:{dashboard_port}/relays'
    client_dash.state.update({"connected": False})

    echo_server = await start_echo_server(port=12000)
    host, echo_port = echo_server.sockets[0].getsockname()

    # test ping
    await ping_relays()

    # open chain and send message
    relays = await fetch_relays()
    reader, writer, conn = await open_chain(relays[:1], host, echo_port)
    writer.write(encrypt_message(conn, b'hello'))
    await writer.drain()
    reply = await read_message(reader, conn)
    assert reply == b'hello'
    writer.close()

    # start client dashboard
    dash_client_port = 8001
    client_dash.RELAY_LIST_URL = f"http://127.0.0.1:{dashboard_port}/relays"
    client_dash_server = run_flask_app(client_dash.app, dash_client_port)
    client_module.RELAY_LIST_URL = client_dash.RELAY_LIST_URL
    # connect via dashboard HTTP api
    async with aiohttp.ClientSession() as session:
        resp = await session.post(f"http://127.0.0.1:{dash_client_port}/connect")
        assert resp.status == 200
        status = await session.get(f'http://127.0.0.1:{dash_client_port}/status')
        data = await status.json()
        assert data['connected'] is True
        await session.post(f'http://127.0.0.1:{dash_client_port}/autokey', json={'enabled': False})
        status2 = await session.get(f'http://127.0.0.1:{dash_client_port}/status')
        data2 = await status2.json()
        assert data2['autokey'] is False
        await session.post(f'http://127.0.0.1:{dash_client_port}/disconnect')
    dash_client_port = None

    echo_server.close()
    await echo_server.wait_closed()
    relay_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await relay_task
    dash_server.shutdown()
    client_dash_server.shutdown()
