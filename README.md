# Alternative WireGuard Relay Network

This repository contains a minimal prototype for a relay network similar to Tor but built on Python with ephemeral key exchange. It consists of three components:

- `dashboard/` – central service that keeps a list of relays.
- `relay/` – volunteer relay server that forwards encrypted traffic.
- `client/` – command line client capable of chat, file transfer, listing relays and pinging.

## Requirements

- Python 3.12
- `cryptography`, `pynacl`, `aiohttp`, `flask`

Install dependencies with:

```bash
pip install cryptography pynacl aiohttp flask
```

## Running the dashboard

```
python3 dashboard/dashboard.py
```

## Starting a relay

```
python3 relay/relay.py --host 0.0.0.0 --port 9000
```

Each relay should POST to `http://dashboard:5000/register` on startup (not implemented in this demo). The dashboard exposes `/relays` for the client to fetch available relays.

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

This code is a minimal prototype and should not be considered secure or production ready.
