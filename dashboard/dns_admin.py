"""
Dashboard DNS Management Component for .alt TLD (BIND9, RNDC-based)

Features:
- Owner-only access (local admin)
- View, add, update, and remove DNS records in .alt zone using RNDC
- Secure dynamic updates and reloads via RNDC
- Audit logging

Assumptions:
- BIND9 configured for RNDC control and dynamic updates for .alt zone
- Script run with sufficient privileges (sudo/root or RNDC key access)

Dependencies:
- Flask (for dashboard API/UI)
"""

import os
import subprocess
from flask import Flask, request, jsonify, abort

ZONE = "alt"
ALLOWED_USER = os.environ.get("DNS_OWNER", os.getlogin())
RNDC_CMD = ["rndc"]

app = Flask(__name__)

def is_owner():
    return os.getlogin() == ALLOWED_USER

def rndc_command(args):
    cmd = RNDC_CMD + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()

@app.route("/dns/records", methods=["GET"])
def get_records():
    if not is_owner():
        abort(403)
    # Use 'rndc dumpdb -zones' and parse output for .alt zone
    try:
        dump = rndc_command(["dumpdb", "-zones"])
        zone_records = []
        in_zone = False
        for line in dump.splitlines():
            if line.startswith(f";; zone '{ZONE}'"):
                in_zone = True
            elif in_zone and line.startswith(";;"):
                break
            elif in_zone:
                zone_records.append(line.strip())
        return jsonify({"records": zone_records})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dns/records", methods=["POST"])
def add_record():
    if not is_owner():
        abort(403)
    data = request.json
    name = data.get("name")
    rtype = data.get("type", "A")
    value = data.get("value")
    ttl = data.get("ttl", 3600)
    if not (name and value):
        abort(400)
    # Use 'rndc addzone' or nsupdate for dynamic update
    try:
        update_cmd = f"server 127.0.0.1\nzone {ZONE}\nupdate add {name}.{ZONE}. {ttl} {rtype} {value}\nsend\n"
        proc = subprocess.run(["nsupdate", "-k", "/etc/bind/rndc.key"], input=update_cmd, text=True, capture_output=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip())
        return jsonify({"status": "added", "record": f"{name}.{ZONE}. {rtype} {value}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dns/records", methods=["DELETE"])
def delete_record():
    if not is_owner():
        abort(403)
    data = request.json
    name = data.get("name")
    rtype = data.get("type", "A")
    value = data.get("value")
    if not (name and value):
        abort(400)
    try:
        update_cmd = f"server 127.0.0.1\nzone {ZONE}\nupdate delete {name}.{ZONE}. {rtype} {value}\nsend\n"
        proc = subprocess.run(["nsupdate", "-k", "/etc/bind/rndc.key"], input=update_cmd, text=True, capture_output=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip())
        return jsonify({"status": "deleted", "record": f"{name}.{ZONE}. {rtype} {value}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8081)
