"""Relay node implementation with IPv6 ULA support."""

import asyncio
import json
import argparse
import os
import sys
import logging
import random
import contextlib
import ipaddress
import aiohttp
from typing import Optional, Tuple, Dict, Any

# Allow running the relay directly from its directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tunnel import handshake, encrypt_message, read_message
from .network import AddressManager, NetworkConfig
from .wireguard import WireGuardConfig, WireGuardManager

logger = logging.getLogger(__name__)

class Relay:
    """Relay node with IPv6 support and WireGuard integration."""
    
    def __init__(self, host: str, port: int, network_config: Optional[NetworkConfig] = None):
        self.host = host
        self.port = port
        
        # Initialize network configuration
        self.network_config = network_config or NetworkConfig()
        
        # Set up WireGuard config if not provided
        if not self.network_config.wireguard_config:
            private_key, public_key = WireGuardManager.generate_keypair()
            self.network_config.wireguard_keys[public_key] = private_key
            self.network_config.wireguard_config = WireGuardConfig(
                private_key=private_key,
                public_key=public_key,
                listen_port=self.network_config.wireguard_port,
                interface="wg0"
            )
        
        self.addr_manager = AddressManager(self.network_config)
        self._ipv6_addr: Optional[ipaddress.IPv6Address] = None
        self._interface = self.network_config.wireguard_config.interface
        self._active_peers: Dict[str, Dict[str, Any]] = {}
    
    async def setup(self):
        """Set up the relay with IPv6 addressing and WireGuard."""
        try:
            # Allocate IPv6 address for this relay
            self._ipv6_addr, netmask = self.addr_manager.allocate_relay_address()
            logger.info("Allocated IPv6 address: %s/%s", self._ipv6_addr, netmask)
            
            # Set up WireGuard interface with IPv6 address
            self.addr_manager.setup_wireguard_interface(self._interface, self._ipv6_addr)
            
            # Log WireGuard public key for peer connections
            logger.info("WireGuard public key: %s", self.network_config.wireguard_config.public_key[:8] + "...")
            
        except Exception as e:
            logger.error("Failed to set up relay networking: %s", e)
            raise
    
    async def add_peer(self, peer_info: Dict[str, Any]) -> None:
        """Add a peer relay to the mesh using WireGuard."""
        peer_id = f"{peer_info['host']}:{peer_info['port']}"
        if peer_id not in self._active_peers:
            self._active_peers[peer_id] = peer_info
            
            if 'ipv6_addr' in peer_info and 'wireguard_pubkey' in peer_info:
                peer_addr = ipaddress.IPv6Address(peer_info['ipv6_addr'])
                
                # Configure WireGuard peer
                allowed_ips = [
                    str(self.addr_manager.config.relay_subnet),
                    str(self.addr_manager.config.client_subnet),
                    str(self.addr_manager.config.service_subnet)
                ]
                
                endpoint = f"{peer_info['host']}:{peer_info.get('wireguard_port', self.network_config.wireguard_port)}"
                
                # Add peer to WireGuard interface
                self.addr_manager._wireguard.add_peer(
                    public_key=peer_info['wireguard_pubkey'],
                    endpoint=endpoint,
                    allowed_ips=allowed_ips,
                    ipv6_addr=peer_addr
                )
                
                # Add routes for this peer's networks
                self.addr_manager.add_route('relay',
                    str(self.addr_manager.config.relay_subnet),
                    str(peer_addr))
                self.addr_manager.add_route('client',
                    str(self.addr_manager.config.client_subnet),
                    str(peer_addr))
                self.addr_manager.add_route('service',
                    str(self.addr_manager.config.service_subnet),
                    str(peer_addr))
                
                # Apply the new routes
                self.addr_manager.apply_routes()
                
                logger.info("Added WireGuard peer %s at %s",
                          peer_info['wireguard_pubkey'][:8], endpoint)
    
    async def remove_peer(self, peer_info: Dict[str, Any]) -> None:
        """Remove a peer relay from the mesh."""
        peer_id = f"{peer_info['host']}:{peer_info['port']}"
        if peer_id in self._active_peers:
            if 'ipv6_addr' in peer_info:
                peer_addr = ipaddress.IPv6Address(peer_info['ipv6_addr'])
                
                # Remove WireGuard peer if public key exists
                if 'wireguard_pubkey' in peer_info:
                    self.addr_manager._wireguard.remove_peer(peer_info['wireguard_pubkey'])
                
                # Remove routes for this peer
                self.addr_manager.remove_route('relay',
                    str(self.addr_manager.config.relay_subnet),
                    str(peer_addr))
                self.addr_manager.remove_route('client',
                    str(self.addr_manager.config.client_subnet),
                    str(peer_addr))
                self.addr_manager.remove_route('service',
                    str(self.addr_manager.config.service_subnet),
                    str(peer_addr))
                
                # Apply route changes
                self.addr_manager.apply_routes()
                
                logger.info("Removed peer %s and associated routes", peer_id)
            
            del self._active_peers[peer_id]

async def forward(reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 in_conn: Any,
                 out_conn: Optional[Any] = None,
                 is_ipv6: bool = False) -> None:
    """Forward traffic between connections."""
    while True:
        data = await read_message(reader, in_conn)
        if data is None:
            break
        
        if out_conn:
            # Forwarding between encrypted tunnels
            writer.write(await encrypt_message(out_conn, reader, writer, data))
        else:
            # Final hop - forward directly to target
            # For IPv6, ensure proper packet encapsulation
            if is_ipv6:
                # Strip any tunnel headers if present
                # This is a placeholder - actual implementation would depend
                # on the tunneling protocol used
                writer.write(data)
            else:
                writer.write(data)
        await writer.drain()
    writer.close()
    logger.debug('Forward loop ended')

async def handle_client(reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter,
                       register_callback,
                       relay: Relay) -> None:
    """Handle an incoming client connection."""
    try:
        in_conn, info = await handshake(reader, writer, initiator=False)
        logger.info('Client connected with info %s', info)
        
        chain = info.get('chain', [])
        target_host = info.get('target_host')
        target_port = info.get('target_port')
        
        if not chain and not target_host:
            logger.debug('Received fake traffic handshake')
            return
            
        if chain:
            next_hop = chain.pop(0)
            next_info = {
                'chain': chain,
                'target_host': target_host,
                'target_port': target_port,
                'ipv6_addr': str(relay._ipv6_addr)  # Include our IPv6 address
            }
            
            # Connect to next relay
            next_reader, next_writer = await asyncio.open_connection(
                next_hop['host'],
                next_hop['port']
            )
            
            out_conn, _ = await handshake(
                next_reader,
                next_writer,
                info=next_info,
                initiator=True
            )
            
            logger.debug('Forwarding to next relay %s:%s',
                        next_hop['host'], next_hop['port'])
            
        else:
            # Final hop - connect to target
            next_reader, next_writer = await asyncio.open_connection(
                target_host,
                target_port
            )
            out_conn = None
        
        await register_callback(True)
        
        if out_conn:
            await asyncio.gather(
                forward(reader, next_writer, in_conn, out_conn),
                forward(next_reader, writer, out_conn, in_conn)
            )
        else:
            # Determine if target supports IPv6
            is_ipv6 = False
            try:
                addr = ipaddress.ip_address(target_host)
                is_ipv6 = isinstance(addr, ipaddress.IPv6Address)
            except ValueError:
                pass
            
            await asyncio.gather(
                forward(reader, next_writer, in_conn, None, is_ipv6),
                forward(next_reader, writer, None, in_conn, is_ipv6)
            )
            
    except Exception as e:
        logger.error('Error: %s', e)
    finally:
        await register_callback(False)
        writer.close()

async def generate_fake_traffic(host: str,
                              port: int,
                              dashboard_url: str,
                              relay: Relay) -> None:
    """Generate fake traffic between relays to mask real traffic patterns."""
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(f"{dashboard_url}/relays") as resp:
                    relays = await resp.json()
                
                # Filter out ourselves
                others = [r for r in relays if r['host'] != host or r['port'] != port]
                
                if others:
                    dest = random.choice(others)
                    # Add peer if not already known
                    await relay.add_peer(dest)
                    
                    # Generate fake traffic
                    r, w = await asyncio.open_connection(dest['host'], dest['port'])
                    conn, _ = await handshake(r, w, info={'fake': True}, initiator=True)
                    w.write(await encrypt_message(conn, r, w, os.urandom(8)))
                    await w.drain()
                    w.close()
                    logger.debug('Sent fake traffic to %s:%s',
                               dest['host'], dest['port'])
                    
            except Exception as exc:
                logger.debug('Fake traffic error: %s', exc)
            
            await asyncio.sleep(random.uniform(5, 15))

async def run_server(host: str,
                    port: int,
                    register_callback,
                    dashboard_url: str = "http://localhost:5000") -> None:
    """Run the relay server."""
    # Initialize relay with IPv6 support
    relay = Relay(host, port)
    await relay.setup()
    
    # Start server
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, register_callback, relay),
        host,
        port
    )
    
    logger.info('Relay running on %s:%s with IPv6 address %s',
                host, port, relay._ipv6_addr)
    
    async with server:
        fake_task = asyncio.create_task(
            generate_fake_traffic(host, port, dashboard_url, relay)
        )
        try:
            await server.serve_forever()
        finally:
            fake_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await fake_task

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--dashboard', default='http://localhost:5000')
    args = parser.parse_args()
    
    async def dummy(active):
        pass
    
    logging.basicConfig(level=logging.INFO,
                       format='%(levelname)s %(message)s')
    
    asyncio.run(run_server(args.host, args.port, dummy, args.dashboard))
