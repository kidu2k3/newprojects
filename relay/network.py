"""Network configuration and routing management for relay mesh."""

import ipaddress
import random
import json
import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .wireguard import WireGuardConfig, WireGuardManager

logger = logging.getLogger(__name__)

@dataclass
class NetworkConfig:
    """Network configuration for the relay mesh."""
    ula_prefix: str = "fd42:1337:beef::/48"  # Base ULA prefix for the network
    relay_subnet: str = "fd42:1337:beef:0::/64"  # Subnet for relay nodes
    client_subnet: str = "fd42:1337:beef:1::/64"  # Subnet for client nodes
    service_subnet: str = "fd42:1337:beef:2::/64"  # Subnet for internal services
    
    # WireGuard configuration
    wireguard_config: Optional[WireGuardConfig] = None
    wireguard_port: int = 51820  # Default WireGuard port
    wireguard_keys: Dict[str, str] = field(default_factory=dict)  # pubkey -> privkey mapping

class AddressManager:
    """Manages IPv6 ULA address allocation and routing."""
    
    def __init__(self, config: NetworkConfig = NetworkConfig()):
        self.config = config
        self._relay_net = ipaddress.IPv6Network(config.relay_subnet)
        self._client_net = ipaddress.IPv6Network(config.client_subnet)
        self._service_net = ipaddress.IPv6Network(config.service_subnet)
        
        # Track allocated addresses
        self._allocated_relay: Set[ipaddress.IPv6Address] = set()
        self._allocated_client: Set[ipaddress.IPv6Address] = set()
        self._allocated_service: Set[ipaddress.IPv6Address] = set()
        
        # Track routing table
        self._routes: Dict[str, List[Dict]] = {
            'relay': [],  # Relay mesh routes
            'client': [], # Client subnet routes
            'service': [] # Service subnet routes
        }
        
        # Initialize WireGuard manager if config provided
        self._wireguard: Optional[WireGuardManager] = None
        if config.wireguard_config:
            self._wireguard = WireGuardManager(config.wireguard_config)
        
        # Load persisted state if exists
        self._load_state()
    
    def _load_state(self):
        """Load persisted network state."""
        state_file = os.path.join(os.path.dirname(__file__), 'network_state.json')
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    self._allocated_relay = {
                        ipaddress.IPv6Address(addr) for addr in state.get('relay_addrs', [])
                    }
                    self._allocated_client = {
                        ipaddress.IPv6Address(addr) for addr in state.get('client_addrs', [])
                    }
                    self._allocated_service = {
                        ipaddress.IPv6Address(addr) for addr in state.get('service_addrs', [])
                    }
                    self._routes = state.get('routes', {
                        'relay': [],
                        'client': [],
                        'service': []
                    })
                logger.info("Loaded network state with %d allocated addresses", 
                          len(self._allocated_relay) + len(self._allocated_client) + len(self._allocated_service))
            except Exception as e:
                logger.error("Failed to load network state: %s", e)
    
    def _save_state(self):
        """Persist network state."""
        state = {
            'relay_addrs': [str(addr) for addr in self._allocated_relay],
            'client_addrs': [str(addr) for addr in self._allocated_client],
            'service_addrs': [str(addr) for addr in self._allocated_service],
            'routes': self._routes
        }
        state_file = os.path.join(os.path.dirname(__file__), 'network_state.json')
        try:
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
            logger.debug("Saved network state")
        except Exception as e:
            logger.error("Failed to save network state: %s", e)
    
    def _allocate_from_subnet(self, subnet: ipaddress.IPv6Network, 
                            allocated: Set[ipaddress.IPv6Address]) -> ipaddress.IPv6Address:
        """Allocate an address from a subnet, avoiding already allocated ones."""
        # Generate random addresses until we find an unallocated one
        max_attempts = 100  # Prevent infinite loops
        for _ in range(max_attempts):
            # Generate a random interface ID (last 64 bits)
            interface_id = random.getrandbits(64)
            # Combine network prefix with random interface ID
            network_int = int(subnet.network_address)
            addr_int = (network_int & ~((1 << 64) - 1)) | interface_id
            addr = ipaddress.IPv6Address(addr_int)
            
            if addr not in allocated and addr in subnet:
                return addr
        
        raise RuntimeError(f"Failed to allocate address from {subnet} after {max_attempts} attempts")

    def allocate_relay_address(self) -> Tuple[ipaddress.IPv6Address, str]:
        """Allocate a new relay address from the relay subnet."""
        addr = self._allocate_from_subnet(self._relay_net, self._allocated_relay)
        self._allocated_relay.add(addr)
        self._save_state()
        return addr, str(self._relay_net.netmask)
    
    def allocate_client_address(self) -> Tuple[ipaddress.IPv6Address, str]:
        """Allocate a new client address from the client subnet."""
        addr = self._allocate_from_subnet(self._client_net, self._allocated_client)
        self._allocated_client.add(addr)
        self._save_state()
        return addr, str(self._client_net.netmask)
    
    def allocate_service_address(self) -> Tuple[ipaddress.IPv6Address, str]:
        """Allocate a new service address from the service subnet."""
        addr = self._allocate_from_subnet(self._service_net, self._allocated_service)
        self._allocated_service.add(addr)
        self._save_state()
        return addr, str(self._service_net.netmask)
    
    def release_address(self, addr: ipaddress.IPv6Address):
        """Release an allocated address back to the pool."""
        addr_obj = ipaddress.IPv6Address(addr)
        if addr_obj in self._allocated_relay:
            self._allocated_relay.remove(addr_obj)
        elif addr_obj in self._allocated_client:
            self._allocated_client.remove(addr_obj)
        elif addr_obj in self._allocated_service:
            self._allocated_service.remove(addr_obj)
        self._save_state()
    
    def add_route(self, route_type: str, destination: str, via: str, metric: int = 1):
        """Add a route to the routing table."""
        if route_type not in self._routes:
            raise ValueError(f"Invalid route type: {route_type}")
        
        route = {
            'destination': str(ipaddress.IPv6Network(destination)),
            'via': str(ipaddress.IPv6Address(via)),
            'metric': metric
        }
        
        # Check for duplicate routes
        if route not in self._routes[route_type]:
            self._routes[route_type].append(route)
            self._save_state()
    
    def remove_route(self, route_type: str, destination: str, via: str):
        """Remove a route from the routing table."""
        if route_type not in self._routes:
            raise ValueError(f"Invalid route type: {route_type}")
        
        route = {
            'destination': str(ipaddress.IPv6Network(destination)),
            'via': str(ipaddress.IPv6Address(via)),
        }
        
        self._routes[route_type] = [
            r for r in self._routes[route_type]
            if not (r['destination'] == route['destination'] and r['via'] == route['via'])
        ]
        self._save_state()
    
    def get_routes(self, route_type: Optional[str] = None) -> Dict[str, List[Dict]]:
        """Get current routing table."""
        if route_type:
            if route_type not in self._routes:
                raise ValueError(f"Invalid route type: {route_type}")
            return {route_type: self._routes[route_type]}
        return self._routes.copy()
    
    def setup_wireguard_interface(self, interface: str, address: ipaddress.IPv6Address):
        """Configure WireGuard interface with IPv6 address."""
        if not self._wireguard:
            # Generate new keypair if needed
            if not self.config.wireguard_keys:
                private_key, public_key = WireGuardManager.generate_keypair()
                self.config.wireguard_keys[public_key] = private_key
                self.config.wireguard_config = WireGuardConfig(
                    private_key=private_key,
                    public_key=public_key,
                    listen_port=self.config.wireguard_port,
                    interface=interface
                )
            self._wireguard = WireGuardManager(self.config.wireguard_config)
        
        # Set up the WireGuard interface with our IPv6 address
        self._wireguard.setup_interface(address, str(self._relay_net.netmask))
        logger.info("Configured WireGuard interface %s with address %s", interface, address)
    
    def apply_routes(self):
        """Apply routes to the system routing table."""
        # This is a placeholder for the actual route configuration
        # In production, this would use pyroute2 or similar to configure routes
        logger.info("Applying routes: %s", self._routes)
