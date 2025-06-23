"""
Configuration management for client app.

Features:
- Load and save configuration from JSON file
- Update and retrieve settings programmatically
- Default config file: client_config.json

Config options:
- relays: list of relay addresses
- interface_name: name of virtual interface
- address: IPv6 address/subnet
- dns_servers: list of DNS server addresses
- other client-specific settings

Usage:
    from client.config import load_config, save_config, update_config, get_config

"""

import os
import json

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "client_config.json")

_config = {}

def load_config(path=DEFAULT_CONFIG_PATH):
    global _config
    if os.path.exists(path):
        with open(path, "r") as f:
            _config = json.load(f)
    else:
        _config = {
            "relays": [],
            "interface_name": "altnet0",
            "address": "fd00::1/64",
            "dns_servers": [],
        }
    return _config

def save_config(path=DEFAULT_CONFIG_PATH):
    with open(path, "w") as f:
        json.dump(_config, f, indent=2)

def update_config(updates: dict, path=DEFAULT_CONFIG_PATH):
    _config.update(updates)
    save_config(path)

def get_config():
    return _config

# Auto-load config on import
load_config()
