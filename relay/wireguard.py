"""WireGuard interface management and configuration."""

import os
import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import ipaddress

logger = logging.getLogger(__name__)

@dataclass
class WireGuardConfig:
    """WireGuard configuration parameters."""
    private_key: str
    public_key: str
    listen_port: int
    interface: str = "wg0"
    persistent_keepalive: int = 25

class WireGuardManager:
    """Manages WireGuard interface configuration and peer setup."""
    
    def __init__(self, config: WireGuardConfig):
        self.config = config
        self._peers: Dict[str, Dict] = {}  # pubkey -> peer_info
        self._load_state()

    def _load_state(self):
        """Load persisted WireGuard state."""
        state_file = os.path.join(os.path.dirname(__file__), 'wireguard_state.json')
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    self._peers = state.get('peers', {})
                logger.info("Loaded WireGuard state with %d peers", len(self._peers))
            except Exception as e:
                logger.error("Failed to load WireGuard state: %s", e)

    def _save_state(self):
        """Persist WireGuard state."""
        state = {
            'peers': self._peers
        }
        state_file = os.path.join(os.path.dirname(__file__), 'wireguard_state.json')
        try:
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
            logger.debug("Saved WireGuard state")
        except Exception as e:
            logger.error("Failed to save WireGuard state: %s", e)

    def setup_interface(self, ipv6_addr: ipaddress.IPv6Address, netmask: str):
        """Set up WireGuard interface with IPv6 address."""
        try:
            # Create the WireGuard interface
            subprocess.run(['sudo', 'ip', 'link', 'add', self.config.interface, 'type', 'wireguard'],
                         check=True)
            
            # Set up private key
            with open(f'/etc/wireguard/{self.config.interface}.key', 'w') as f:
                f.write(self.config.private_key)
            os.chmod(f'/etc/wireguard/{self.config.interface}.key', 0o600)
            
            # Configure WireGuard interface
            subprocess.run([
                'sudo', 'wg', 'set', self.config.interface,
                'private-key', f'/etc/wireguard/{self.config.interface}.key',
                'listen-port', str(self.config.listen_port)
            ], check=True)
            
            # Configure IPv6 address
            subprocess.run([
                'sudo', 'ip', '-6', 'address', 'add',
                f'{ipv6_addr}/{netmask}',
                'dev', self.config.interface
            ], check=True)
            
            # Bring up interface
            subprocess.run(['sudo', 'ip', 'link', 'set', 'up', 'dev', self.config.interface],
                         check=True)
            
            logger.info("WireGuard interface %s configured with address %s/%s",
                       self.config.interface, ipv6_addr, netmask)
            
        except subprocess.CalledProcessError as e:
            logger.error("Failed to set up WireGuard interface: %s", e)
            raise

    def add_peer(self, public_key: str, endpoint: Optional[str],
                allowed_ips: List[str], ipv6_addr: ipaddress.IPv6Address):
        """Add or update a WireGuard peer."""
        try:
            cmd = [
                'sudo', 'wg', 'set', self.config.interface,
                'peer', public_key,
                'persistent-keepalive', str(self.config.persistent_keepalive),
                'allowed-ips', ','.join(allowed_ips)
            ]
            
            if endpoint:
                cmd.extend(['endpoint', endpoint])
            
            subprocess.run(cmd, check=True)
            
            # Store peer info
            self._peers[public_key] = {
                'endpoint': endpoint,
                'allowed_ips': allowed_ips,
                'ipv6_addr': str(ipv6_addr)
            }
            self._save_state()
            
            logger.info("Added WireGuard peer %s with endpoint %s",
                       public_key[:8], endpoint)
            
        except subprocess.CalledProcessError as e:
            logger.error("Failed to add WireGuard peer: %s", e)
            raise

    def remove_peer(self, public_key: str):
        """Remove a WireGuard peer."""
        try:
            subprocess.run([
                'sudo', 'wg', 'set', self.config.interface,
                'peer', public_key,
                'remove'
            ], check=True)
            
            if public_key in self._peers:
                del self._peers[public_key]
                self._save_state()
            
            logger.info("Removed WireGuard peer %s", public_key[:8])
            
        except subprocess.CalledProcessError as e:
            logger.error("Failed to remove WireGuard peer: %s", e)
            raise

    def get_interface_info(self) -> Dict:
        """Get current WireGuard interface information."""
        try:
            result = subprocess.run([
                'sudo', 'wg', 'show', self.config.interface, 'dump'
            ], capture_output=True, check=True)
            
            lines = result.stdout.decode().strip().split('\n')
            info = {
                'interface': self.config.interface,
                'listen_port': self.config.listen_port,
                'peers': {}
            }
            
            # Parse wg show output
            for line in lines:
                fields = line.strip().split('\t')
                if len(fields) >= 8:  # Peer entry with full data
                    public_key = fields[0]
                    info['peers'][public_key] = {
                        'endpoint': fields[3],
                        'allowed_ips': [x for x in fields[7].split(',') if x],
                        'latest_handshake': fields[4],
                        'transfer': {
                            'received': fields[5],
                            'sent': fields[6]
                        }
                    }
                elif len(fields) >= 3:  # Minimal peer entry
                    public_key = fields[0]
                    info['peers'][public_key] = {
                        'endpoint': fields[2] if len(fields) > 2 else None,
                        'allowed_ips': [],
                        'latest_handshake': None,
                        'transfer': {
                            'received': '0',
                            'sent': '0'
                        }
                    }
            
            return info
            
        except subprocess.CalledProcessError as e:
            logger.error("Failed to get interface info: %s", e)
            raise

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate a new WireGuard keypair."""
        try:
            # Generate private key
            privkey = subprocess.run(['wg', 'genkey'],
                                  capture_output=True, check=True)
            private_key = privkey.stdout.decode().strip()
            
            # Generate public key
            pubkey = subprocess.run(['wg', 'pubkey'],
                                  input=private_key.encode(),
                                  capture_output=True, check=True)
            public_key = pubkey.stdout.decode().strip()
            
            return private_key, public_key
            
        except subprocess.CalledProcessError as e:
            logger.error("Failed to generate WireGuard keypair: %s", e)
            raise
