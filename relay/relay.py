import asyncio
import json
import argparse
import os
import sys

# Allow running the relay directly from its directory
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from tunnel import handshake, encrypt_message, read_message

async def forward(reader, writer, in_box, out_box):
    while True:
        data = await read_message(reader, in_box)
        if data is None:
            break
        writer.write(encrypt_message(out_box, data))
        await writer.drain()
    writer.close()

async def handle_client(reader, writer, register_callback):
    try:
        in_box, info = await handshake(reader, writer)
        chain = info.get('chain', [])
        target_host = info.get('target_host')
        target_port = info.get('target_port')
        if chain:
            next_hop = chain.pop(0)
            next_info = {'chain': chain, 'target_host': target_host, 'target_port': target_port}
            next_reader, next_writer = await asyncio.open_connection(next_hop['host'], next_hop['port'])
            out_box, _ = await handshake(next_reader, next_writer, info=next_info)
        else:
            next_reader, next_writer = await asyncio.open_connection(target_host, target_port)
            out_box = None
        await register_callback(True)
        if out_box:
            await asyncio.gather(
                forward(reader, next_writer, in_box, out_box),
                forward(next_reader, writer, out_box, in_box)
            )
        else:
            # final hop
            async def to_target():
                while True:
                    data = await read_message(reader, in_box)
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
                    writer.write(encrypt_message(in_box, data))
                    await writer.drain()
                writer.close()
            await asyncio.gather(to_target(), from_target())
    except Exception as e:
        print('error:', e)
    finally:
        await register_callback(False)
        writer.close()

async def run_server(host, port, register_callback):
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, register_callback), host, port)
    print(f'Relay running on {host}:{port}')
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=9000)
    args = parser.parse_args()

    async def dummy(active):
        pass

    asyncio.run(run_server(args.host, args.port, dummy))
