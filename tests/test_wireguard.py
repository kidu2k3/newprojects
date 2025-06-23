"""Test WireGuard interface configuration and peer management."""

import os
import sys
import pytest
import ipaddress
import json
import subprocess
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from relay.wireguard import WireGuardConfig, WireGuardManager

# Test data
TEST_PRIVKEY = "YAnUluK7n9ZQVxqKBUqm7zQZYr+dJxGxGBgwi6tVN0Y="
TEST_PUBKEY = "h1CYEdqF9ElQHZ3Nr9rM7c4upANh6DfC5uI4xRVn5T0="
TEST_PEER_PUBKEY = "KBUqm7zQZYr+dJxGxGBgwi6tVN0YYAnUluK7n9ZQVxq="

@pytest.fixture
def wg_config():
    """Create a test WireGuard configuration."""
    return WireGuardConfig(
        private_key=TEST_PRIVKEY,
        public_key=TEST_PUBKEY,
        listen_port=51820,
        interface="wg0"
    )

@pytest.fixture
def wg_manager(wg_config, tmp_path):
    """Create a test WireGuard manager with mocked state file."""
    with patch("relay.wireguard.os.path.join", return_value=str(tmp_path / "wireguard_state.json")):
        return WireGuardManager(wg_config)

def test_wireguard_config():
    """Test WireGuard configuration object."""
    config = WireGuardConfig(
        private_key=TEST_PRIVKEY,
        public_key=TEST_PUBKEY,
        listen_port=51820
    )
    assert config.private_key == TEST_PRIVKEY
    assert config.public_key == TEST_PUBKEY
    assert config.listen_port == 51820
    assert config.interface == "wg0"  # Default value
    assert config.persistent_keepalive == 25  # Default value

def test_generate_keypair():
    """Test WireGuard keypair generation."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(stdout=TEST_PRIVKEY.encode(), check=True),
            MagicMock(stdout=TEST_PUBKEY.encode(), check=True)
        ]
        private_key, public_key = WireGuardManager.generate_keypair()
        assert private_key.strip() == TEST_PRIVKEY.strip()
        assert public_key.strip() == TEST_PUBKEY.strip()
        assert mock_run.call_count == 2
        
        # Verify correct commands were called
        calls = mock_run.call_args_list
        assert calls[0].args[0] == ['wg', 'genkey']
        assert calls[1].args[0] == ['wg', 'pubkey']

def test_setup_interface(wg_manager, tmp_path):
    """Test WireGuard interface setup."""
    addr = ipaddress.IPv6Address("fd42:1337:beef::1")
    netmask = "64"
    
    key_file = tmp_path / "wg0.key"
    with patch("relay.wireguard.open", create=True) as mock_open, \
         patch("subprocess.run") as mock_run, \
         patch("os.chmod") as mock_chmod:
        mock_file = mock_open.return_value.__enter__.return_value
        wg_manager.setup_interface(addr, netmask)
        
        # Verify correct commands were called
        calls = mock_run.call_args_list
        assert len(calls) == 4
        
        # Check interface creation
        assert calls[0].args[0] == ['sudo', 'ip', 'link', 'add', 'wg0', 'type', 'wireguard']
        
        # Check private key setup
        assert calls[1].args[0] == ['sudo', 'wg', 'set', 'wg0',
                                   'private-key', f'/etc/wireguard/wg0.key',
                                   'listen-port', '51820']
        
        # Check IPv6 address configuration
        assert calls[2].args[0] == ['sudo', 'ip', '-6', 'address', 'add',
                                   f'{addr}/64', 'dev', 'wg0']
        
        # Check interface up
        assert calls[3].args[0] == ['sudo', 'ip', 'link', 'set', 'up', 'dev', 'wg0']
        
        # Verify private key was written
        mock_file.write.assert_called_once_with(TEST_PRIVKEY)
        mock_chmod.assert_called_once_with(f'/etc/wireguard/wg0.key', 0o600)

def test_add_peer(wg_manager):
    """Test adding a WireGuard peer."""
    peer_addr = ipaddress.IPv6Address("fd42:1337:beef::2")
    allowed_ips = ["fd42:1337:beef::/48"]
    endpoint = "192.0.2.1:51820"
    
    with patch("subprocess.run") as mock_run:
        wg_manager.add_peer(TEST_PEER_PUBKEY, endpoint, allowed_ips, peer_addr)
        
        # Verify peer was added
        assert TEST_PEER_PUBKEY in wg_manager._peers
        assert wg_manager._peers[TEST_PEER_PUBKEY]['endpoint'] == endpoint
        assert wg_manager._peers[TEST_PEER_PUBKEY]['allowed_ips'] == allowed_ips
        assert wg_manager._peers[TEST_PEER_PUBKEY]['ipv6_addr'] == str(peer_addr)
        
        # Check WireGuard command
        mock_run.assert_called_once()
        cmd = mock_run.call_args.args[0]
        assert cmd[0:3] == ['sudo', 'wg', 'set']
        assert TEST_PEER_PUBKEY in cmd
        assert endpoint in cmd
        assert allowed_ips[0] in cmd[cmd.index('allowed-ips')+1]

def test_remove_peer(wg_manager):
    """Test removing a WireGuard peer."""
    # First add a peer
    peer_addr = ipaddress.IPv6Address("fd42:1337:beef::2")
    with patch("subprocess.run") as mock_run:
        wg_manager.add_peer(TEST_PEER_PUBKEY, "192.0.2.1:51820", 
                          ["fd42:1337:beef::/48"], peer_addr)
        
        # Then remove it
        wg_manager.remove_peer(TEST_PEER_PUBKEY)
        
        # Verify peer was removed
        assert TEST_PEER_PUBKEY not in wg_manager._peers
        
        # Check remove command
        calls = mock_run.call_args_list
        assert len(calls) == 2
        remove_cmd = calls[1].args[0]
        assert remove_cmd[0:3] == ['sudo', 'wg', 'set']
        assert TEST_PEER_PUBKEY in remove_cmd
        assert 'remove' in remove_cmd

def test_get_interface_info(wg_manager):
    """Test getting WireGuard interface information."""
    # Format: pubkey privkey port endpoint handshake rx tx allowed_ips
    wg_output = f"{TEST_PUBKEY}\tprivkey\t51820\t192.0.2.1:51820\t"
    wg_output += "300\t1000\t2000\tfd42:1337:beef::/48\n"
    
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout=wg_output.encode(),
            check=True
        )
        info = wg_manager.get_interface_info()
        
        assert info['interface'] == "wg0"
        assert info['listen_port'] == 51820
        assert TEST_PUBKEY in info['peers']
        peer_info = info['peers'][TEST_PUBKEY]
        assert peer_info['endpoint'] == "192.0.2.1:51820"
        assert peer_info['allowed_ips'] == ["fd42:1337:beef::/48"]
        assert peer_info['latest_handshake'] == "300"
        assert peer_info['transfer'] == {'received': '1000', 'sent': '2000'}

def test_state_persistence(tmp_path):
    """Test saving and loading WireGuard state."""
    state_file = tmp_path / "wireguard_state.json"
    
    with patch("relay.wireguard.os.path.join", return_value=str(state_file)):
        # Create manager and add peer
        manager1 = WireGuardManager(WireGuardConfig(
            private_key=TEST_PRIVKEY,
            public_key=TEST_PUBKEY,
            listen_port=51820
        ))
        
        peer_addr = ipaddress.IPv6Address("fd42:1337:beef::2")
        with patch("subprocess.run"):
            manager1.add_peer(TEST_PEER_PUBKEY, "192.0.2.1:51820",
                            ["fd42:1337:beef::/48"], peer_addr)
        
        # Create new manager (should load saved state)
        manager2 = WireGuardManager(WireGuardConfig(
            private_key=TEST_PRIVKEY,
            public_key=TEST_PUBKEY,
            listen_port=51820
        ))
        
        # Verify state was loaded
        assert TEST_PEER_PUBKEY in manager2._peers
        assert manager2._peers[TEST_PEER_PUBKEY]['endpoint'] == "192.0.2.1:51820"
        assert manager2._peers[TEST_PEER_PUBKEY]['allowed_ips'] == ["fd42:1337:beef::/48"]
        assert manager2._peers[TEST_PEER_PUBKEY]['ipv6_addr'] == str(peer_addr)

def test_error_handling():
    """Test error handling in WireGuard operations."""
    error_msg = "Command failed"
    
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, [], error_msg)
        manager = WireGuardManager(WireGuardConfig(
            private_key=TEST_PRIVKEY,
            public_key=TEST_PUBKEY,
            listen_port=51820
        ))
        
        # Test interface setup error
        with pytest.raises(subprocess.CalledProcessError):
            manager.setup_interface(
                ipaddress.IPv6Address("fd42:1337:beef::1"), "64"
            )
        
        # Test peer addition error
        with pytest.raises(subprocess.CalledProcessError):
            manager.add_peer(
                TEST_PEER_PUBKEY,
                "192.0.2.1:51820",
                ["fd42:1337:beef::/48"],
                ipaddress.IPv6Address("fd42:1337:beef::2")
            )
        
        # Test peer removal error
        with pytest.raises(subprocess.CalledProcessError):
            manager.remove_peer(TEST_PEER_PUBKEY)

if __name__ == '__main__':
    pytest.main([__file__])
