import argparse
import contextlib
import asyncio
import logging
import aiohttp

from relay.relay import run_server

async def register(host, port, dashboard_url):
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

async def main(host, port, dashboard_url):
    await register(host, port, dashboard_url)
    heartbeat_task = asyncio.create_task(heartbeat_loop(host, port, dashboard_url))
    async def dummy(active):
        pass
    try:
        await run_server(host, port, dummy, dashboard_url)
    finally:
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat_task

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Start a relay server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--dashboard", default="http://localhost:5000")
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port, args.dashboard))
