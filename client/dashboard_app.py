import asyncio
import json
from flask import Flask, jsonify, request
import aiohttp
import os
import sys

# Ensure tunnel module is importable when run directly
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from tunnel import handshake

RELAY_LIST_URL = 'http://localhost:5000/relays'

app = Flask(__name__)

state = {
    'connected': False,
    'relay': None,
    'autokey': True,
    'pending_peer': None,
    'box': None,
    'reader': None,
    'writer': None,
}

def reset_connection():
    if state['writer']:
        state['writer'].close()
    state.update({'connected': False, 'relay': None, 'box': None, 'reader': None, 'writer': None})

async def connect_first_relay():
    async with aiohttp.ClientSession() as session:
        async with session.get(RELAY_LIST_URL) as resp:
            relays = await resp.json()
    if not relays:
        raise RuntimeError('no relays available')
    relay = relays[0]
    reader, writer = await asyncio.open_connection(relay['host'], relay['port'])
    box, _ = await handshake(reader, writer, info={'client': True})
    state.update({'connected': True, 'relay': relay, 'box': box, 'reader': reader, 'writer': writer})

@app.route('/connect', methods=['POST'])
def connect():
    if state['connected']:
        return 'already connected', 400
    asyncio.run(connect_first_relay())
    return 'ok'

@app.route('/disconnect', methods=['POST'])
def disconnect():
    reset_connection()
    return 'ok'

@app.route('/autokey', methods=['POST'])
def toggle_autokey():
    data = request.json
    state['autokey'] = bool(data.get('enabled', True))
    return 'ok'

@app.route('/status')
def status():
    out = {k: v for k, v in state.items() if k not in {'box', 'reader', 'writer'}}
    return jsonify(out)

@app.route('/request', methods=['POST'])
def incoming_request():
    data = request.json
    state['pending_peer'] = data.get('peer')
    return 'ok'

@app.route('/respond', methods=['POST'])
def respond():
    data = request.json
    accept = data.get('accept')
    peer = state.pop('pending_peer', None)
    if accept and peer and state['autokey']:
        # In a real system, handshake with peer would occur here
        return 'accepted', 200
    return 'declined', 200

if __name__ == '__main__':
    app.run(port=8000)
