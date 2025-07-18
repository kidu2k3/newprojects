import asyncio
import random
import json
import argparse
from tunnel import handshake, encrypt_message, read_message
import aiohttp

RELAY_LIST_URL = 'http://localhost:5000/relays'

async def fetch_relays():
    async with aiohttp.ClientSession() as session:
        async with session.get(RELAY_LIST_URL) as resp:
            return await resp.json()

async def open_chain(relays, dest_host, dest_port):
    if not relays:
        raise ValueError('no relays')
    chain = [{'host': r['host'], 'port': r['port']} for r in relays[1:]]
    reader, writer = await asyncio.open_connection(relays[0]['host'], relays[0]['port'])
    info = {'chain': chain, 'target_host': dest_host, 'target_port': dest_port}
    box = await handshake(reader, writer, initiator=True, info=info)
    return reader, writer, box

async def chat(dest_host, dest_port, hop_count=3):
    relays = await fetch_relays()
    random.shuffle(relays)
    selected = relays[:hop_count]
    reader, writer, box = await open_chain(selected, dest_host, dest_port)
    print('Connected to chat peer. type messages:')
    async def read_loop():
        while True:
            data = await read_message(reader, box)
            if data is None:
                break
            print('peer:', data.decode())
    asyncio.create_task(read_loop())
    try:
        while True:
            msg = await asyncio.get_event_loop().run_in_executor(None, input)
            if not msg:
                break
            writer.write(encrypt_message(box, msg.encode()))
            await writer.drain()
    finally:
        writer.close()

async def send_file(dest_host, dest_port, path, hop_count=3):
    relays = await fetch_relays()
    random.shuffle(relays)
    selected = relays[:hop_count]
    reader, writer, box = await open_chain(selected, dest_host, dest_port)
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            writer.write(encrypt_message(box, chunk))
            await writer.drain()
    writer.write(encrypt_message(box, b''))
    await writer.drain()
    writer.close()

async def ping_relays(count=1):
    relays = await fetch_relays()
    results = []
    for r in relays:
        try:
            reader, writer = await asyncio.open_connection(r['host'], r['port'])
            box = await handshake(reader, writer, initiator=True, info={'ping': True})
            writer.close()
            results.append((r, 'ok'))
        except Exception as e:
            results.append((r, 'fail'))
    for r, res in results:
        print(f"{r['host']}:{r['port']} -> {res}")

if __name__ == '__main__':
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
    else:
        parser.print_help()
