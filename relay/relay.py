import asyncio
import json
import argparse
import os
import sys
import logging
import random
import contextlib
import aiohttp

# Allow running the relay directly from its directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tunnel import handshake, encrypt_message, read_message

logger = logging.getLogger(__name__)

async def forward(reader, writer, in_conn, out_conn):
    while True:
        data = await read_message(reader, in_conn)
        if data is None:
            break
        writer.write(encrypt_message(out_conn, data))
        await writer.drain()
    writer.close()
    logger.debug('forward loop ended')

async def handle_client(reader, writer, register_callback):
    try:
        in_conn, info = await handshake(reader, writer, initiator=False)
        logger.info('Client connected with info %s', info)
        chain = info.get('chain', [])
        target_host = info.get('target_host')
        target_port = info.get('target_port')
        if not chain and not target_host:
            logger.debug('Received fake traffic handshake')
            return
        if chain:
            next_hop = chain.pop(0)
            next_info = {'chain': chain, 'target_host': target_host, 'target_port': target_port}
            next_reader, next_writer = await asyncio.open_connection(next_hop['host'], next_hop['port'])
            out_conn, _ = await handshake(next_reader, next_writer, info=next_info, initiator=True)
            logger.debug('Forwarding to next relay %s:%s', next_hop['host'], next_hop['port'])
        else:
            next_reader, next_writer = await asyncio.open_connection(target_host, target_port)
            out_conn = None
        await register_callback(True)
        if out_conn:
            await asyncio.gather(
                forward(reader, next_writer, in_conn, out_conn),
                forward(next_reader, writer, out_conn, in_conn)
            )
        else:
            # final hop
            async def to_target():
                while True:
                    data = await read_message(reader, in_conn)
                    if data is None:
                        break
                    next_writer.write(data)
                    await next_writer.drain()
                next_writer.close()
            async def from_target():
                while True:
                    data = await next_reader.read(4096)
                    if not data:
                        break
                    writer.write(encrypt_message(in_conn, data))
                    await writer.drain()
                writer.close()
            await asyncio.gather(to_target(), from_target())
    except Exception as e:
        logger.error('error: %s', e)
    finally:
        await register_callback(False)
        writer.close()

async def generate_fake_traffic(host, port, dashboard_url):
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(f"{dashboard_url}/relays") as resp:
                    relays = await resp.json()
                others = [r for r in relays if r['host'] != host or r['port'] != port]
                if others:
                    dest = random.choice(others)
                    r, w = await asyncio.open_connection(dest['host'], dest['port'])
                    conn, _ = await handshake(r, w, info={'fake': True}, initiator=True)
                    w.write(encrypt_message(conn, os.urandom(8)))
                    await w.drain()
                    w.close()
                    logger.debug('Sent fake traffic to %s:%s', dest['host'], dest['port'])
            except Exception as exc:
                logger.debug('fake traffic error: %s', exc)
            await asyncio.sleep(random.uniform(5, 15))

async def run_server(host, port, register_callback, dashboard_url="http://localhost:5000"):
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, register_callback), host, port)
    logger.info('Relay running on %s:%s', host, port)
    async with server:
        fake_task = asyncio.create_task(generate_fake_traffic(host, port, dashboard_url))
        try:
            await server.serve_forever()
        finally:
            fake_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await fake_task

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--dashboard', default='http://localhost:5000')
    args = parser.parse_args()

    async def dummy(active):
        pass

    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    asyncio.run(run_server(args.host, args.port, dummy, args.dashboard))
