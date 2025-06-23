import asyncio
import random
import json
import argparse
import os
import sys
import subprocess
import logging

# Allow running the script directly from the client directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tunnel import handshake, encrypt_message, read_message
import aiohttp

logger = logging.getLogger(__name__)

RELAY_LIST_URL = 'http://localhost:5000/relays'

async def fetch_relays():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(RELAY_LIST_URL) as resp:
                relays = await resp.json()
                logger.debug("Fetched %d relays", len(relays))
                return relays
    except Exception as exc:
        logger.error("failed to fetch relays: %s", exc)
        return []

def create_virtual_interface(name: str = 'altnet0', address: str = 'fd00::1/64') -> None:
    """Create a Linux TUN device using ``ip`` commands."""
    if os.name != 'posix':
        print('Virtual interfaces are only supported on Linux-like systems')
        return
    if os.geteuid() != 0:
        print('Root privileges required to create interfaces')
        return
    cmds = [
        ['ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun'],
        ['ip', 'addr', 'add', address, 'dev', name],
        ['ip', 'link', 'set', name, 'up'],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            # Ignore if the interface already exists
            if 'File exists' in str(exc):
                continue
            logger.error('Command %s failed: %s', cmd, exc)
            return
    logger.info('Interface %s configured with %s', name, address)

async def open_chain(relays, dest_host, dest_port):
    if not relays:
        raise ValueError('no relays')
    chain = [{'host': r['host'], 'port': r['port']} for r in relays[1:]]
    reader, writer = await asyncio.open_connection(relays[0]['host'], relays[0]['port'])
    info = {'chain': chain, 'target_host': dest_host, 'target_port': dest_port}
    conn, _ = await handshake(reader, writer, info=info, initiator=True)
    logger.debug('Opened chain via %s', [r['host'] for r in relays])
    return reader, writer, conn

async def chat(dest_host, dest_port, hop_count=3):
    relays = await fetch_relays()
    random.shuffle(relays)
    selected = relays[:hop_count]
    logger.info('Connecting through %d hops', len(selected))
    reader, writer, conn = await open_chain(selected, dest_host, dest_port)
    print('Connected to chat peer. type messages:')
    async def read_loop():
        while True:
            data = await read_message(reader, conn)
            if data is None:
                break
            print('peer:', data.decode())
    asyncio.create_task(read_loop())
    try:
        while True:
            msg = await asyncio.get_event_loop().run_in_executor(None, input)
            if not msg:
                break
            writer.write(encrypt_message(conn, msg.encode()))
            await writer.drain()
    finally:
        writer.close()

async def send_file(dest_host, dest_port, path, hop_count=3):
    relays = await fetch_relays()
    random.shuffle(relays)
    selected = relays[:hop_count]
    logger.info('Sending %s via %d hops', path, len(selected))
    reader, writer, conn = await open_chain(selected, dest_host, dest_port)
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            writer.write(encrypt_message(conn, chunk))
            await writer.drain()
    writer.write(encrypt_message(conn, b''))
    await writer.drain()
    writer.close()

async def ping_relays(count=1):
    relays = await fetch_relays()
    results = []
    for r in relays:
        try:
            reader, writer = await asyncio.open_connection(r['host'], r['port'])
            conn, _ = await handshake(reader, writer, info={'ping': True}, initiator=True)
            writer.close()
            results.append((r, 'ok'))
        except Exception as e:
            logger.warning('Ping to %s:%s failed: %s', r['host'], r['port'], e)
            results.append((r, 'fail'))
    for r, res in results:
        print(f"{r['host']}:{r['port']} -> {res}")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd')
    chat_p = sub.add_parser('chat')
    chat_p.add_argument('host')
    chat_p.add_argument('port', type=int)
    chat_p.add_argument('--hops', type=int, default=3)

    send_p = sub.add_parser('send')
    send_p.add_argument('host')
    send_p.add_argument('port', type=int)
    send_p.add_argument('file')
    send_p.add_argument('--hops', type=int, default=3)

    sub.add_parser('list')
    sub.add_parser('ping')
    iface_p = sub.add_parser('iface')
    iface_p.add_argument('--name', default='altnet0')
    iface_p.add_argument('--addr', default='fd00::1/64')

    args = parser.parse_args()

    if args.cmd == 'list':
        relays = asyncio.run(fetch_relays())
        for r in relays:
            print(r['host'], r['port'])
    elif args.cmd == 'ping':
        asyncio.run(ping_relays())
    elif args.cmd == 'chat':
        asyncio.run(chat(args.host, args.port, args.hops))
    elif args.cmd == 'send':
        asyncio.run(send_file(args.host, args.port, args.file, args.hops))
    elif args.cmd == 'iface':
        create_virtual_interface(args.name, args.addr)
    else:
        parser.print_help()
