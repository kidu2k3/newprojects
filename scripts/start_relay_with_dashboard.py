import argparse
import contextlib
import asyncio
import logging
import threading
import aiohttp
from werkzeug.serving import make_server

from relay.relay import run_server
from dashboard.dashboard import app as dashboard_app

async def register_relay(host, port, dashboard_url):
    async with aiohttp.ClientSession() as session:
        await session.post(f"{dashboard_url}/register", json={"host": host, "port": port})

async def heartbeat_loop(host, port, dashboard_url):
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                await session.post(f"{dashboard_url}/heartbeat", json={"host": host, "port": port})
            except Exception as exc:
                logging.debug("heartbeat failed: %s", exc)
            await asyncio.sleep(10)

class DashboardServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self._server = make_server(host, port, dashboard_app)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def shutdown(self):
        self._server.shutdown()
        self._thread.join()

async def main(relay_host, relay_port, dash_host, dash_port):
    dash = DashboardServer(dash_host, dash_port)
    dash.start()
    dashboard_url = f"http://{dash_host}:{dash_port}"
    await register_relay(relay_host, relay_port, dashboard_url)
    heartbeat_task = asyncio.create_task(heartbeat_loop(relay_host, relay_port, dashboard_url))

    async def dummy(active):
        pass
    try:
        await run_server(relay_host, relay_port, dummy, dashboard_url)
    finally:
        heartbeat_task.cancel()
        dash.shutdown()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat_task

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Start relay and dashboard")
    parser.add_argument("--relay-host", default="0.0.0.0")
    parser.add_argument("--relay-port", type=int, default=9000)
    parser.add_argument("--dashboard-host", default="0.0.0.0")
    parser.add_argument("--dashboard-port", type=int, default=5000)
    args = parser.parse_args()

    asyncio.run(main(args.relay_host, args.relay_port, args.dashboard_host, args.dashboard_port))
