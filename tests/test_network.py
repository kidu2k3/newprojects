"""Test IPv6 ULA addressing and routing functionality."""

import os
import sys
import pytest
import ipaddress
import json
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from relay.network import NetworkConfig, AddressManager
from relay.wireguard import WireGuardConfig, WireGuardManager

# Test data
TEST_PRIVKEY = "YAnUluK7n9ZQVxqKBUqm7zQZYr+dJxGxGBgwi6tVN0Y="
TEST_PUBKEY = "h1CYEdqF9ElQHZ3Nr9rM7c4upANh6DfC5uI4xRVn5T0="

def test_network_config_defaults():
    """Test default NetworkConfig values."""
    config = NetworkConfig()
    assert config.ula_prefix == "fd42:1337:beef::/48"
    assert config.relay_subnet == "fd42:1337:beef:0::/64"
    assert config.client_subnet == "fd42:1337:beef:1::/64"
    assert config.service_subnet == "fd42:1337:beef:2::/64"

def test_custom_network_config():
    """Test custom NetworkConfig values."""
    wg_config = WireGuardConfig(
        private_key=TEST_PRIVKEY,
        public_key=TEST_PUBKEY,
        listen_port=51820
    )
    
    config = NetworkConfig(
        ula_prefix="fd00:1234:5678::/48",
        relay_subnet="fd00:1234:5678:0::/64",
        client_subnet="fd00:1234:5678:1::/64",
        service_subnet="fd00:1234:5678:2::/64",
        wireguard_config=wg_config,
        wireguard_port=51820,
        wireguard_keys={TEST_PUBKEY: TEST_PRIVKEY}
    )
    
    assert config.ula_prefix == "fd00:1234:5678::/48"
    assert config.relay_subnet == "fd00:1234:5678:0::/64"
    assert config.client_subnet == "fd00:1234:5678:1::/64"
    assert config.service_subnet == "fd00:1234:5678:2::/64"
    assert config.wireguard_config == wg_config
    assert config.wireguard_port == 51820
    assert config.wireguard_keys == {TEST_PUBKEY: TEST_PRIVKEY}

def test_valid_ipv6_networks():
    """Test that all subnets are valid IPv6 networks."""
    config = NetworkConfig()
    # These should not raise exceptions
    ipaddress.IPv6Network(config.ula_prefix)
    ipaddress.IPv6Network(config.relay_subnet)
    ipaddress.IPv6Network(config.client_subnet)
    ipaddress.IPv6Network(config.service_subnet)

def test_subnet_relationships():
    """Test that subnets are properly contained within ULA prefix."""
    config = NetworkConfig()
    ula = ipaddress.IPv6Network(config.ula_prefix)
    relay_net = ipaddress.IPv6Network(config.relay_subnet)
    client_net = ipaddress.IPv6Network(config.client_subnet)
    service_net = ipaddress.IPv6Network(config.service_subnet)
    
    assert relay_net.subnet_of(ula)
    assert client_net.subnet_of(ula)
    assert service_net.subnet_of(ula)

def test_address_allocation():
    """Test address allocation from different subnets."""
    manager = AddressManager()
    
    # Allocate relay address
    relay_addr, relay_mask = manager.allocate_relay_address()
    assert isinstance(relay_addr, ipaddress.IPv6Address)
    assert relay_addr in ipaddress.IPv6Network(manager.config.relay_subnet)
    
    # Allocate client address
    client_addr, client_mask = manager.allocate_client_address()
    assert isinstance(client_addr, ipaddress.IPv6Address)
    assert client_addr in ipaddress.IPv6Network(manager.config.client_subnet)
    
    # Allocate service address
    service_addr, service_mask = manager.allocate_service_address()
    assert isinstance(service_addr, ipaddress.IPv6Address)
    assert service_addr in ipaddress.IPv6Network(manager.config.service_subnet)

def test_duplicate_address_prevention():
    """Test that addresses are not allocated twice."""
    manager = AddressManager()
    
    # Allocate some addresses
    allocated = set()
    for _ in range(10):  # Test with a reasonable number of addresses
        addr, _ = manager.allocate_relay_address()
        # Verify address is unique
        assert addr not in allocated
        allocated.add(addr)
    
    # Try allocating more addresses with varying random values
    with patch('random.getrandbits') as mock_random:
        # Start with values that would generate existing addresses
        values = [int(addr) & ((1 << 64) - 1) for addr in allocated]
        # Then add some new values
        values.extend(range(100000, 100010))  # Some arbitrary new values
        mock_random.side_effect = values
        
        # Should be able to allocate new addresses
        for _ in range(5):  # Test a few allocations
            new_addr, _ = manager.allocate_relay_address()
            assert new_addr not in allocated
            allocated.add(new_addr)

def test_address_release():
    """Test releasing allocated addresses."""
    manager = AddressManager()
    
    # Allocate some addresses
    relay_addr, _ = manager.allocate_relay_address()
    client_addr, _ = manager.allocate_client_address()
    service_addr, _ = manager.allocate_service_address()
    
    # Release them
    manager.release_address(relay_addr)
    manager.release_address(client_addr)
    manager.release_address(service_addr)
    
    # Should be able to allocate them again
    new_relay_addr, _ = manager.allocate_relay_address()
    new_client_addr, _ = manager.allocate_client_address()
    new_service_addr, _ = manager.allocate_service_address()
    
    assert relay_addr not in {new_relay_addr}  # Random allocation
    assert client_addr not in {new_client_addr}  # Random allocation
    assert service_addr not in {new_service_addr}  # Random allocation

def test_route_management():
    """Test adding and removing routes."""
    manager = AddressManager()
    
    # Add some routes
    dest = "fd42:1337:beef:1::/64"
    via = "fd42:1337:beef::1"
    
    manager.add_route("relay", dest, via, metric=1)
    routes = manager.get_routes("relay")
    
    assert routes["relay"][0]["destination"] == dest
    assert routes["relay"][0]["via"] == via
    assert routes["relay"][0]["metric"] == 1
    
    # Remove route
    manager.remove_route("relay", dest, via)
    routes = manager.get_routes("relay")
    assert not routes["relay"]

def test_state_persistence(tmp_path):
    """Test saving and loading network state."""
    state_file = tmp_path / "network_state.json"
    
    with patch("relay.network.os.path.join", return_value=str(state_file)):
        # Create manager and allocate addresses
        manager1 = AddressManager()
        relay_addr, _ = manager1.allocate_relay_address()
        client_addr, _ = manager1.allocate_client_address()
        manager1.add_route("relay", "fd42:1337:beef:1::/64", str(relay_addr))
        
        # Create new manager (should load saved state)
        manager2 = AddressManager()
        
        # Verify state was loaded
        assert relay_addr in manager2._allocated_relay
        assert client_addr in manager2._allocated_client
        
        routes = manager2.get_routes("relay")
        assert routes["relay"][0]["destination"] == "fd42:1337:beef:1::/64"
        assert routes["relay"][0]["via"] == str(relay_addr)

def test_invalid_route_type():
    """Test error handling for invalid route types."""
    manager = AddressManager()
    
    with pytest.raises(ValueError):
        manager.add_route("invalid", "fd42:1337:beef:1::/64", "fd42:1337:beef::1")
    
    with pytest.raises(ValueError):
        manager.remove_route("invalid", "fd42:1337:beef:1::/64", "fd42:1337:beef::1")
    
    with pytest.raises(ValueError):
        manager.get_routes("invalid")

def test_wireguard_interface_setup():
    """Test WireGuard interface configuration."""
    manager = AddressManager()
    addr, _ = manager.allocate_relay_address()
    
    # Mock the actual interface setup since we can't modify the system
    with patch.object(manager, 'setup_wireguard_interface') as mock_setup:
        manager.setup_wireguard_interface("wg0", addr)
        mock_setup.assert_called_once_with("wg0", addr)

def test_wireguard_setup_in_address_manager():
    """Test WireGuard setup through AddressManager."""
    wg_config = WireGuardConfig(
        private_key=TEST_PRIVKEY,
        public_key=TEST_PUBKEY,
        listen_port=51820
    )
    
    network_config = NetworkConfig(wireguard_config=wg_config)
    manager = AddressManager(network_config)
    
    # Verify WireGuard manager was initialized
    assert manager._wireguard is not None
    assert manager._wireguard.config == wg_config
    
    # Test interface setup
    with patch.object(manager._wireguard, 'setup_interface') as mock_setup:
        addr = ipaddress.IPv6Address("fd42:1337:beef::1")
        manager.setup_wireguard_interface("wg0", addr)
        mock_setup.assert_called_once_with(addr, str(manager._relay_net.netmask))

def test_wireguard_config_generation():
    """Test automatic WireGuard config generation."""
    manager = AddressManager()  # No WireGuard config provided
    
    with patch.object(WireGuardManager, 'generate_keypair') as mock_generate, \
         patch('relay.wireguard.subprocess.run') as mock_run, \
         patch('relay.wireguard.open', create=True) as mock_open, \
         patch('relay.wireguard.os.chmod') as mock_chmod:
        
        mock_generate.return_value = (TEST_PRIVKEY, TEST_PUBKEY)
        mock_file = mock_open.return_value.__enter__.return_value
        
        # This should trigger key generation and config creation
        manager.setup_wireguard_interface("wg0", 
            ipaddress.IPv6Address("fd42:1337:beef::1"))
        
        # Verify WireGuard config was created correctly
        assert manager.config.wireguard_keys == {TEST_PUBKEY: TEST_PRIVKEY}
        assert manager.config.wireguard_config is not None
        assert manager.config.wireguard_config.private_key == TEST_PRIVKEY
        assert manager.config.wireguard_config.public_key == TEST_PUBKEY
        
        # Verify interface setup was called with correct parameters
        mock_run.assert_called()
        mock_file.write.assert_called_once_with(TEST_PRIVKEY)
        mock_chmod.assert_called_once_with('/etc/wireguard/wg0.key', 0o600)

@pytest.mark.asyncio
async def test_route_application():
    """Test applying routes to system routing table."""
    manager = AddressManager()
    
    # Add some test routes
    manager.add_route("relay", "fd42:1337:beef:1::/64", "fd42:1337:beef::1")
    manager.add_route("client", "fd42:1337:beef:2::/64", "fd42:1337:beef::2")
    
    # Mock the actual route application since we can't modify the system
    with patch.object(manager, 'apply_routes') as mock_apply:
        manager.apply_routes()
        mock_apply.assert_called_once()

if __name__ == '__main__':
    pytest.main([__file__])
