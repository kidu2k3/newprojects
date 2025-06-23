"""Utility functions for establishing encrypted tunnels."""

from __future__ import annotations

import asyncio
import json
import logging
import struct
from typing import Any, Dict, Tuple

from nacl.public import Box, PrivateKey, PublicKey

logger = logging.getLogger(__name__)


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
    logger.debug("Generated ephemeral key")
    writer.write(priv.public_key.encode())
    logger.debug("Sent public key")
    await writer.drain()

    peer_pub = await asyncio.wait_for(reader.read(32), timeout)
    if len(peer_pub) < 32:
        raise ConnectionError("peer did not send public key")
    box = Box(priv, PublicKey(peer_pub))
    logger.debug("Received peer key")

    payload = json.dumps(info or {}).encode()
    enc = box.encrypt(payload)
    writer.write(struct.pack("!I", len(enc)) + enc)
    logger.debug("Sent encrypted metadata")
    await writer.drain()

    length_bytes = await asyncio.wait_for(reader.read(4), timeout)
    if len(length_bytes) < 4:
        raise ConnectionError("handshake failed")
    length = struct.unpack("!I", length_bytes)[0]
    peer_enc = await asyncio.wait_for(reader.read(length), timeout)
    peer_info = json.loads(box.decrypt(peer_enc))
    logger.debug("Received peer metadata: %s", peer_info)
    return box, peer_info

def encrypt_message(box, data):
    enc = box.encrypt(data)
    logger.debug("Encrypting %d bytes", len(data))
    return struct.pack('!I', len(enc)) + enc

async def read_message(reader, box):
    len_bytes = await reader.read(4)
    if not len_bytes:
        return None
    length = struct.unpack('!I', len_bytes)[0]
    enc = await reader.read(length)
    logger.debug("Decrypting %d bytes", length)
    try:
        return box.decrypt(enc)
    except Exception as exc:
        logger.error("failed to decrypt message: %s", exc)
        return None
