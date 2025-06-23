import asyncio
import json
import logging
from flask import Flask, jsonify, request
import aiohttp
import os
import sys

# Ensure tunnel module is importable when run directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tunnel import handshake

logger = logging.getLogger(__name__)

RELAY_LIST_URL = 'http://localhost:5000/relays'

app = Flask(__name__)

state = {
    'connected': False,
    'relay': None,
    'autokey': True,
    'pending_peer': None,
    'session': None,
    'reader': None,
    'writer': None,
}

def reset_connection():
    if state['writer']:
        state['writer'].close()
    state.update({'connected': False, 'relay': None, 'session': None, 'reader': None, 'writer': None})
    logger.info('Connection reset')

async def connect_first_relay():
    async with aiohttp.ClientSession() as session:
        async with session.get(RELAY_LIST_URL) as resp:
            relays = await resp.json()
    if not relays:
        raise RuntimeError('no relays available')
    relay = relays[0]
    logger.info('Connecting to relay %s:%s', relay['host'], relay['port'])
    reader, writer = await asyncio.open_connection(relay['host'], relay['port'])
    conn, _ = await handshake(reader, writer, info={'client': True}, initiator=True)
    state.update({'connected': True, 'relay': relay, 'session': conn, 'reader': reader, 'writer': writer})

@app.route('/connect', methods=['POST'])
def connect():
    if state['connected']:
        return 'already connected', 400
    try:
        asyncio.run(connect_first_relay())
    except Exception as exc:
        logger.error('connect failed: %s', exc)
        return 'error', 500
    return 'ok'

@app.route('/disconnect', methods=['POST'])
def disconnect():
    reset_connection()
    logger.info('Disconnected from relay')
    return 'ok'

@app.route('/autokey', methods=['POST'])
def toggle_autokey():
    data = request.json
    state['autokey'] = bool(data.get('enabled', True))
    logger.info('Auto key exchange set to %s', state['autokey'])
    return 'ok'

@app.route('/status')
def status():
    out = {k: v for k, v in state.items() if k not in {'session', 'reader', 'writer'}}
    return jsonify(out)

@app.route('/request', methods=['POST'])
def incoming_request():
    data = request.json
    state['pending_peer'] = data.get('peer')
    logger.info('Incoming peer request from %s', state['pending_peer'])
    return 'ok'

@app.route('/respond', methods=['POST'])
def respond():
    data = request.json
    accept = data.get('accept')
    peer = state.pop('pending_peer', None)
    if accept and peer and state['autokey']:
        # In a real system, handshake with peer would occur here
        logger.info('Accepted peer %s', peer)
        return 'accepted', 200
    logger.info('Declined peer %s', peer)
    return 'declined', 200

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    app.run(port=8000)
