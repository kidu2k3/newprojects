"""Integration tests for relay mesh with IPv6 and WireGuard support."""

import os
import sys
import pytest
import pytest_asyncio
import asyncio
import logging
import ipaddress
import json
from typing import List, Tuple, Dict
from unittest.mock import patch, AsyncMock, MagicMock

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from relay.network import NetworkConfig, AddressManager
from relay.relay import Relay, run_server
from relay.wireguard import WireGuardConfig, WireGuardManager
from tunnel import handshake, encrypt_message, read_message
from tests.test_handshake import generate_keypair

# Test data
TEST_PRIVKEY = "YAnUluK7n9ZQVxqKBUqm7zQZYr+dJxGxGBgwi6tVN0Y="
TEST_PUBKEY = "h1CYEdqF9ElQHZ3Nr9rM7c4upANh6DfC5uI4xRVn5T0="

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class TestRelay:
    """Helper class for testing relay nodes."""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.active = False
        self.relay = None
        self.server = None
        self._task = None
    
    async def start(self, wg_config: WireGuardConfig = None):
        """Start the relay server with optional WireGuard config."""
        with patch('subprocess.run') as mock_run, \
             patch('relay.wireguard.open', create=True) as mock_open, \
             patch('relay.wireguard.os.chmod') as mock_chmod:
            
            mock_file = mock_open.return_value.__enter__.return_value
            
            if not wg_config:
                if not hasattr(self, '_test_keypair'):
                    self._test_keypair = (TEST_PRIVKEY, TEST_PUBKEY)
                private_key, public_key = self._test_keypair
                wg_config = WireGuardConfig(
                    private_key=private_key,
                    public_key=public_key,
                    listen_port=51820
                )
            
            network_config = NetworkConfig(wireguard_config=wg_config)
            self.relay = Relay(self.host, self.port, network_config)
            await self.relay.setup()
        
        async def register(active: bool):
            self.active = active
        
        self.server = await asyncio.start_server(
            lambda r, w: self.relay.handle_client(r, w, register),
            self.host,
            self.port
        )
        self._task = asyncio.create_task(self.server.serve_forever())
        
        logger.info("Started relay on %s:%d with IPv6 %s",
                   self.host, self.port, self.relay._ipv6_addr)
    
    async def stop(self):
        """Stop the relay server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self.relay and self.relay._ipv6_addr:
            self.relay.addr_manager.release_address(self.relay._ipv6_addr)

@pytest_asyncio.fixture
async def relay_network():
    """Set up a network of test relays."""
    relays: List[TestRelay] = []
    
    with patch('subprocess.run') as mock_run, \
         patch('relay.wireguard.open', create=True) as mock_open, \
         patch('relay.wireguard.os.chmod') as mock_chmod:
        
        mock_file = mock_open.return_value.__enter__.return_value
        mock_run.return_value = MagicMock(check=True)

        try:
            # Create 3 relays with unique WireGuard keys
            for i, port in enumerate(range(3)):
                relay = TestRelay('127.0.0.1', 9000 + port)
                wg_config = WireGuardConfig(
                    private_key=f"private{i}",
                    public_key=f"public{i}",
                    listen_port=51820 + i
                )
                await relay.start(wg_config)
                relays.append(relay)
                
                # Add peer relationships with WireGuard configs
                for other in relays[:-1]:
                    peer_info = {
                        'host': other.host,
                        'port': other.port,
                        'ipv6_addr': str(other.relay._ipv6_addr),
                        'wireguard_pubkey': other.relay.network_config.wireguard_config.public_key,
                        'wireguard_port': other.relay.network_config.wireguard_port
                    }
                    await relay.relay.add_peer(peer_info)
                    
                    peer_info = {
                        'host': relay.host,
                        'port': relay.port,
                        'ipv6_addr': str(relay.relay._ipv6_addr),
                        'wireguard_pubkey': relay.relay.network_config.wireguard_config.public_key,
                        'wireguard_port': relay.relay.network_config.wireguard_port
                    }
                    await other.relay.add_peer(peer_info)
            
            yield relays
    
        finally:
            for relay in relays:
                await relay.stop()

@pytest.mark.asyncio
async def test_relay_wireguard_setup():
    """Test basic WireGuard setup of a relay."""
    relay = TestRelay('127.0.0.1', 9000)
    try:
        # Set up relay with WireGuard config
        wg_config = WireGuardConfig(
            private_key=TEST_PRIVKEY,
            public_key=TEST_PUBKEY,
            listen_port=51820
        )
        await relay.start(wg_config)
        
        # Verify WireGuard setup
        assert relay.relay.network_config.wireguard_config is not None
        assert relay.relay.network_config.wireguard_config.public_key == TEST_PUBKEY
        assert relay.relay.addr_manager._wireguard is not None
        
        # Get interface info
        with patch.object(relay.relay.addr_manager._wireguard, 'get_interface_info') as mock_info:
            mock_info.return_value = {
                'interface': 'wg0',
                'listen_port': 51820,
                'peers': {}
            }
            info = relay.relay.addr_manager._wireguard.get_interface_info()
            assert info['interface'] == 'wg0'
            assert info['listen_port'] == 51820
            
    finally:
        await relay.stop()

@pytest.mark.asyncio
async def test_relay_ipv6_setup():
    """Test basic IPv6 setup of a relay."""
    relay = TestRelay('127.0.0.1', 9000)
    try:
        await relay.start()
        
        assert relay.relay._ipv6_addr is not None
        assert isinstance(relay.relay._ipv6_addr, ipaddress.IPv6Address)
        assert relay.relay._ipv6_addr in ipaddress.IPv6Network(relay.relay.addr_manager.config.relay_subnet)
        
    finally:
        await relay.stop()

@pytest.mark.asyncio
async def test_relay_peer_routing(relay_network):
    """Test routing between relay peers."""
    relays = relay_network
    assert len(relays) >= 2
    
    # Check routes between first two relays
    relay1, relay2 = relays[0], relays[1]
    
    routes1 = relay1.relay.addr_manager.get_routes("relay")
    routes2 = relay2.relay.addr_manager.get_routes("relay")
    
    # Verify routes exist in both directions
    assert any(r["via"] == str(relay2.relay._ipv6_addr) for r in routes1["relay"])
    assert any(r["via"] == str(relay1.relay._ipv6_addr) for r in routes2["relay"])

@pytest.mark.asyncio
async def test_wireguard_peer_connectivity():
    """Test WireGuard connectivity between relay peers."""
    relays: List[TestRelay] = []
    
    try:
        # Create two relays with WireGuard
        ports = [9000, 9001]
        for i, port in enumerate(ports):
            relay = TestRelay('127.0.0.1', port)
            wg_config = WireGuardConfig(
                private_key=f"private{i}",
                public_key=f"public{i}",
                listen_port=51820 + i
            )
            await relay.start(wg_config)
            relays.append(relay)
        
        r1, r2 = relays
        
        # Add peer relationships with WireGuard info
        peer_info1 = {
            'host': r1.host,
            'port': r1.port,
            'ipv6_addr': str(r1.relay._ipv6_addr),
            'wireguard_pubkey': r1.relay.network_config.wireguard_config.public_key,
            'wireguard_port': r1.relay.network_config.wireguard_port
        }
        peer_info2 = {
            'host': r2.host,
            'port': r2.port,
            'ipv6_addr': str(r2.relay._ipv6_addr),
            'wireguard_pubkey': r2.relay.network_config.wireguard_config.public_key,
            'wireguard_port': r2.relay.network_config.wireguard_port
        }
        
        # Mock WireGuard interface operations
        with patch.object(WireGuardManager, 'add_peer') as mock_add_peer:
            await r1.relay.add_peer(peer_info2)
            await r2.relay.add_peer(peer_info1)
            
            # Verify WireGuard peers were configured
            assert mock_add_peer.call_count == 2
            
            # Check r1's WireGuard peer setup
            call_args = mock_add_peer.call_args_list[0][1]
            assert call_args['public_key'] == peer_info2['wireguard_pubkey']
            assert str(call_args['ipv6_addr']) == peer_info2['ipv6_addr']
            
            # Check r2's WireGuard peer setup
            call_args = mock_add_peer.call_args_list[1][1]
            assert call_args['public_key'] == peer_info1['wireguard_pubkey']
            assert str(call_args['ipv6_addr']) == peer_info1['ipv6_addr']
            
            # Verify routes were added
            routes1 = r1.relay.addr_manager.get_routes("relay")
            routes2 = r2.relay.addr_manager.get_routes("relay")
            
            assert any(r["via"] == peer_info2['ipv6_addr'] for r in routes1["relay"])
            assert any(r["via"] == peer_info1['ipv6_addr'] for r in routes2["relay"])
    
    finally:
        for relay in relays:
            await relay.stop()

@pytest.mark.asyncio
async def test_multi_hop_relay():
    """Test relaying through multiple hops using IPv6."""
    # Set up 3 relays in a chain
    relays: List[TestRelay] = []
    client_keys = None
    try:
        with patch('subprocess.run') as mock_run, \
             patch('relay.wireguard.open', create=True) as mock_open, \
             patch('relay.wireguard.os.chmod') as mock_chmod:
            mock_file = mock_open.return_value.__enter__.return_value
            mock_run.return_value = MagicMock(check=True)

            # Create relays with unique WireGuard keys
            for i, port in enumerate(range(9000, 9003)):
                relay = TestRelay('127.0.0.1', port)
                wg_config = WireGuardConfig(
                    private_key=f"private{i}",
                    public_key=f"public{i}",
                    listen_port=51820 + i
                )
                await relay.start(wg_config)
                relays.append(relay)
                if relays[-2:]:  # Connect sequential relays
                    r1, r2 = relays[-2:]
                    peer_info1 = {
                        'host': r1.host,
                        'port': r1.port,
                        'ipv6_addr': str(r1.relay._ipv6_addr),
                        'wireguard_pubkey': r1.relay.network_config.wireguard_config.public_key,
                        'wireguard_port': r1.relay.network_config.wireguard_port
                    }
                    peer_info2 = {
                        'host': r2.host,
                        'port': r2.port,
                        'ipv6_addr': str(r2.relay._ipv6_addr),
                        'wireguard_pubkey': r2.relay.network_config.wireguard_config.public_key,
                        'wireguard_port': r2.relay.network_config.wireguard_port
                    }
                    await r1.relay.add_peer(peer_info2)
                    await r2.relay.add_peer(peer_info1)

        # Create an echo server at the end of the chain
        async def echo_server(reader, writer):
            try:
                while True:
                    data = await reader.read(1024)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        echo = await asyncio.start_server(echo_server, '127.0.0.1', 8000)
        async with echo:
            # Connect through the relay chain
            client_keys = {"client": generate_keypair()}
            # Build the routing chain through all relays
            chain = []
            for relay in relays:
                chain.append({
                    'host': relay.host,
                    'port': relay.port,
                    'ipv6_addr': str(relay.relay._ipv6_addr)
                })
            # Connect to first relay
            r1 = relays[0]
            reader, writer = await asyncio.open_connection(r1.host, r1.port)
            try:
                # Perform handshake with routing info
                client_private, client_public = client_keys["client"]
                context, _ = await handshake(
                    reader, writer,
                    static_private=client_private,
                    static_public=client_public,
                    info={
                        'chain': chain[1:],  # Remaining hops
                        'target_host': '127.0.0.1',
                        'target_port': 8000
                    },
                    initiator=True
                )
                # Send test message through chain
                test_msg = b"Hello through IPv6 relay chain!"
                writer.write(await encrypt_message(context, reader, writer, test_msg))
                await writer.drain()
                # Receive echo response
                response = await read_message(reader, context, writer)
                assert response == test_msg
            finally:
                writer.close()
                await writer.wait_closed()
    finally:
        for relay in relays:
            await relay.stop()

if __name__ == '__main__':
    pytest.main([__file__])
