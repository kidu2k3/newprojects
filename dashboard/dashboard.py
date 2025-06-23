from flask import Flask, request, jsonify, render_template
import os
import time
import logging

BASE_DIR = os.path.dirname(__file__)
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))
relays = {}

logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    key = f"{data['host']}:{data['port']}"
    relays[key] = {'host': data['host'], 'port': data['port'], 'last': time.time()}
    logger.info('Registered relay %s', key)
    return 'ok'

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    key = f"{data['host']}:{data['port']}"
    if key in relays:
        relays[key]['last'] = time.time()
        logger.debug('Heartbeat from %s', key)
    return 'ok'

@app.route('/relays', methods=['GET'])
def list_relays():
    now = time.time()
    active = [v for v in relays.values() if now - v['last'] < 60]
    logger.debug('Listing %d active relays', len(active))
    return jsonify(active)

@app.route('/stats', methods=['GET'])
def stats():
    count = len(relays)
    logger.debug('Stats requested: %d relays', count)
    return jsonify({'relay_count': count})

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    app.run(host='0.0.0.0')
