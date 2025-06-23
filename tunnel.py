"""Utility functions for establishing encrypted tunnels."""

from __future__ import annotations

import asyncio
import json
import logging
import struct
from typing import Any, Dict, Tuple

from noise.connection import NoiseConnection

logger = logging.getLogger(__name__)


async def handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    info: Dict[str, Any] | None = None,
    *,
    initiator: bool = True,
    timeout: float = 5.0,
) -> Tuple[NoiseConnection, Dict[str, Any]]:
    """Perform a Noise_NN handshake similar to WireGuard.

    Metadata ``info`` is exchanged as payload in the handshake messages.
    ``initiator`` selects which side sends the first message.
    A ``NoiseConnection`` ready for encryption and the peer's metadata
    dictionary are returned.
    """

    noise = NoiseConnection.from_name(b"Noise_NN_25519_ChaChaPoly_BLAKE2s")
    if initiator:
        noise.set_as_initiator()
    else:
        noise.set_as_responder()
    noise.start_handshake()

    payload = json.dumps(info or {}).encode()

    if initiator:
        msg = noise.write_message(payload)
        writer.write(struct.pack("!H", len(msg)) + msg)
        await writer.drain()

        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout)
        length = struct.unpack("!H", len_bytes)[0]
        resp = await asyncio.wait_for(reader.readexactly(length), timeout)
        peer_payload = noise.read_message(resp)
    else:
        len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout)
        length = struct.unpack("!H", len_bytes)[0]
        data = await asyncio.wait_for(reader.readexactly(length), timeout)
        peer_payload = noise.read_message(data)

        msg = noise.write_message(payload)
        writer.write(struct.pack("!H", len(msg)) + msg)
        await writer.drain()

    peer_info = json.loads(peer_payload.decode() if peer_payload else b"{}")
    logger.debug("Noise handshake complete with info %s", peer_info)
    return noise, peer_info

def encrypt_message(conn: NoiseConnection, data: bytes) -> bytes:
    """Encrypt a payload using the Noise session."""
    enc = conn.encrypt(data)
    logger.debug("Encrypting %d bytes", len(data))
    return struct.pack('!I', len(enc)) + enc

async def read_message(reader: asyncio.StreamReader, conn: NoiseConnection):
    len_bytes = await reader.read(4)
    if not len_bytes:
        return None
    length = struct.unpack('!I', len_bytes)[0]
    enc = await reader.read(length)
    logger.debug("Decrypting %d bytes", length)
    try:
        return conn.decrypt(enc)
    except Exception as exc:
        logger.error("failed to decrypt message: %s", exc)
        return None
