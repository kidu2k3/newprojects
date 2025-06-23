# Alternative WireGuard Relay Network

This repository contains a minimal prototype for a relay network similar to Tor but built on Python with ephemeral key exchange. It consists of three components:

- `dashboard/` – central service that keeps a list of relays.
- `relay/` – volunteer relay server that forwards encrypted traffic.
- `client/` – command line client capable of chat, file transfer, listing relays and pinging.

## Architecture

```
 +-------------+        HTTP           +---------+
 | dashboard/ |<---------------------->| client |
 +-------------+    /relays, stats     +---------+
        ^                                   |
        | register/heartbeat                | encrypted tunnel via relays
   +-----------+                            v
   |  relay/   |----------------------->+---------+
   +-----------+ forwards traffic       | target |
                                        +---------+
```

`tunnel.py` contains the Noise protocol handshake used by both the client and
relay to establish encrypted channels.

## Requirements

- Python 3.12
- `cryptography`, `pynacl`, `aiohttp`, `flask`, `noiseprotocol`

Install runtime dependencies with:

```bash
pip install -r requirements.txt
```

For running the test suite also install the development requirements:

```bash
pip install -r requirements-dev.txt
```

## Running the dashboard

```
python3 dashboard/dashboard.py
```

Open `http://localhost:5000/` in a browser to view a small web dashboard that
shows active relays and overall statistics. The page refreshes every few
seconds to display current information.

## Starting a relay

```
python3 relay/relay.py --host 0.0.0.0 --port 9000
```

Each relay should POST to `http://dashboard:5000/register` on startup (not implemented in this demo). The dashboard exposes `/relays` for the client to fetch available relays.
Relays also generate periodic fake traffic to random peers retrieved from the dashboard. This helps obscure real connections. Use `--dashboard` to point the relay at a custom dashboard URL.

You can also use the convenience script which registers the relay and sends periodic heartbeats:

```
python3 scripts/start_relay.py --host 0.0.0.0 --port 9000 --dashboard http://localhost:5000
```

To start a local dashboard and a relay together:

```
python3 scripts/start_relay_with_dashboard.py --relay-port 9000 --dashboard-port 5000
```

## Client usage

List available relays:

```
python3 client/client.py list
```

Ping relays:

```
python3 client/client.py ping
```

Chat with a peer through the network:

```
python3 client/client.py chat <host> <port> --hops 3
```

Send a file:

```
python3 client/client.py send <host> <port> <file> --hops 3
```

Create a virtual network interface (requires root privileges):

```
sudo python3 client/client.py iface --name altnet0 --addr fd00::1/64
```

### Client dashboard

You can run a small web dashboard to control the client. It allows toggling
automatic key exchange and displays the current connection status. A helper
script is included to launch it:

```
python3 scripts/start_client_dashboard.py --port 8000
```

Use `POST /connect` to establish a connection to the first available relay and
`POST /autokey` with `{"enabled": false}` to disable automatic key exchange.

## Example: single relay with two endpoints

1. Start the dashboard and a relay together:
   ```bash
   python3 scripts/start_relay_with_dashboard.py --relay-port 9000 --dashboard-port 5000
   ```
2. (Optional) If you run the dashboard separately, register your relay manually:
   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"host":"127.0.0.1","port":9000}' http://127.0.0.1:5000/register
   ```
3. Launch a simple server (for example using netcat) to receive messages:
   ```bash
   nc -l -p 10000
   ```
4. Connect through the relay from another shell:
   ```bash
   python3 client/client.py chat 127.0.0.1 10000 --hops 1
   ```
   Typed messages will travel through the relay to the server and responses will appear back in the client.

This code is a minimal prototype and should not be considered secure or production ready.
