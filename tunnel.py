"""Utility functions for establishing encrypted tunnels."""

from __future__ import annotations

import asyncio
import json
import struct
from typing import Any, Dict, Tuple

from nacl.public import Box, PrivateKey, PublicKey


async def handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    info: Dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> Tuple[Box, Dict[str, Any]]:
    """Exchange ephemeral keys and optional metadata.

    Both sides call ``handshake`` simultaneously. A ``Box`` for symmetric
    encryption and the peer's metadata dictionary are returned.
    """

    priv = PrivateKey.generate()
    writer.write(priv.public_key.encode())
    await writer.drain()

    peer_pub = await asyncio.wait_for(reader.read(32), timeout)
    if len(peer_pub) < 32:
        raise ConnectionError("peer did not send public key")
    box = Box(priv, PublicKey(peer_pub))

    payload = json.dumps(info or {}).encode()
    enc = box.encrypt(payload)
    writer.write(struct.pack("!I", len(enc)) + enc)
    await writer.drain()

    length_bytes = await asyncio.wait_for(reader.read(4), timeout)
    if len(length_bytes) < 4:
        raise ConnectionError("handshake failed")
    length = struct.unpack("!I", length_bytes)[0]
    peer_enc = await asyncio.wait_for(reader.read(length), timeout)
    peer_info = json.loads(box.decrypt(peer_enc))
    return box, peer_info

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
