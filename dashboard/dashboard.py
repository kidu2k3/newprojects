from flask import Flask, request, jsonify
import time

app = Flask(__name__)
relays = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    key = f"{data['host']}:{data['port']}"
    relays[key] = {'host': data['host'], 'port': data['port'], 'last': time.time()}
    return 'ok'

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    key = f"{data['host']}:{data['port']}"
    if key in relays:
        relays[key]['last'] = time.time()
    return 'ok'

@app.route('/relays', methods=['GET'])
def list_relays():
    now = time.time()
    return jsonify([v for v in relays.values() if now - v['last'] < 60])

@app.route('/stats', methods=['GET'])
def stats():
    return jsonify({'relay_count': len(relays)})

if __name__ == '__main__':
    app.run(host='0.0.0.0')
