import asyncio
import struct
import json
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as random_bytes

async def handshake(reader, writer, initiator=True, info=None):
    if initiator:
        priv = PrivateKey.generate()
        writer.write(priv.public_key.encode())
        await writer.drain()
        peer_pub = await reader.read(32)
        box = Box(priv, PublicKey(peer_pub))
        payload = json.dumps(info or {}).encode()
        encrypted = box.encrypt(payload)
        writer.write(struct.pack('!I', len(encrypted)) + encrypted)
        await writer.drain()
        return box
    else:
        peer_pub = await reader.read(32)
        priv = PrivateKey.generate()
        writer.write(priv.public_key.encode())
        await writer.drain()
        box = Box(priv, PublicKey(peer_pub))
        length_bytes = await reader.read(4)
        if len(length_bytes) < 4:
            raise ConnectionError('handshake failed')
        length = struct.unpack('!I', length_bytes)[0]
        encrypted = await reader.read(length)
        payload = json.loads(box.decrypt(encrypted))
        return box, payload

def encrypt_message(box, data):
    enc = box.encrypt(data)
    return struct.pack('!I', len(enc)) + enc

async def read_message(reader, box):
    len_bytes = await reader.read(4)
    if not len_bytes:
        return None
    length = struct.unpack('!I', len_bytes)[0]
    enc = await reader.read(length)
    return box.decrypt(enc)
