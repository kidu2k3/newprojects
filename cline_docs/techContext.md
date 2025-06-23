# Technical Context

## Core Technologies

### Network Infrastructure
1. WireGuard
   - Purpose: Encrypted tunnel creation
   - Implementation: WireGuard-go
   - Requirements: Kernel module or userspace implementation

2. IPv6 ULA Space
   - Range: fc00::/7
   - Example Subnet: fd42:1337:beef::/48
   - Purpose: Internal addressing

3. DNS Servers
   - BIND9: Authoritative DNS for .alt domains
   - Unbound/CoreDNS: Recursive resolver for internal lookups
   - RNDC/nsupdate: Secure dynamic DNS management

4. Routing & Mesh
   - BGP (FRR/BIRD): Dynamic routing between relays
   - Overlay: Yggdrasil, cjdns for mesh optimization
   - NAT traversal: TURN/DERP

5. Client GUI
   - Tauri: Cross-platform desktop app for user access (in progress)
   - Status: Basic UI implemented, features pending

6. Content Distribution
   - IPFS, ZeroNet, CDN: Internal/offline content sharing (planned)

7. Authentication & Directory
   - LDAP, Firebase, PKI: Directory/auth server integration (planned)

8. Blockchain/DHT
   - Handshake, Namecoin: Blockchain-based DNS (planned)
   - DHT: Distributed DNS registry (planned)

### Security Components
1. Noise Protocol
   - Pattern: Noise_IK_25519_ChaChaPoly_BLAKE2s
   - Implementation: Python noise library
   - Current Status:
     - ✅ X25519 key exchange implemented
     - ✅ ChaChaPoly encryption working
     - ✅ BLAKE2s hashing integrated
     - 🔄 Edge case handling needed
     - ❌ Security event logging pending

2. Security Parameters
```python
# Current implementation in tunnel.py
MAX_MESSAGE_SIZE = 65535  # Maximum size of encrypted messages
HANDSHAKE_TIMEOUT = 30.0  # Default handshake timeout in seconds
KEY_ROTATION_INTERVAL = 3600  # Rotate session keys every hour
REPLAY_WINDOW = 300  # 5 minute replay protection window
MESSAGES_BEFORE_ROTATION = 100  # Number of messages before key rotation
ROTATION_TIMEOUT = 5.0  # Key rotation timeout in seconds
```

### Backend Services
1. Flask Framework
   - Purpose: Dashboard and API
   - Components:
     - Templates for UI
     - JSON API endpoints
     - Static file serving
   - Status: Basic functionality implemented, authentication pending

2. Python Core
   - Version: 3.8+ recommended (for improved AsyncIO support)
   - Key Libraries:
     - asyncio for async operations (needs error handling improvements)
     - json for data serialization
     - struct for binary data handling
     - typing for type hints
   - Testing Requirements:
     - pytest for unit tests
     - coverage.py for test coverage reporting

## Development Environment

### Project Structure
1. Package Management
   - requirements.txt for production
   - requirements-dev.txt for development

2. Testing Framework
   - pytest for unit tests
   - Integration test suite (needs expansion)
   - Test coverage monitoring needed

### Dependencies
```
Core:
- noise
- flask
- asyncio
- wireguard-tools
- cryptography>=3.4.0

Development:
- pytest>=7.0.0
- black
- flake8
- mypy
- coverage
- pytest-asyncio
- pytest-cov
```

## Technical Constraints

### Performance Limits
1. Message Handling
   - Max message size: 64KB
   - Replay window: 5 minutes
   - Key rotation: Every hour or 100 messages
   - Rotation timeout: 5 seconds

2. Network Constraints
   - IPv6 ULA space only
   - WireGuard compatibility required
   - Reliable internet connection needed
   - Heartbeat interval: 60 seconds

### Security Requirements
1. Cryptographic
   - Strong static key pairs required
   - Noise Protocol compliance mandatory
   - Regular key rotation
   - Edge case handling needed:
     - Silent failure recovery
     - Timeout handling
     - Connection loss recovery

2. Protocol Requirements
   - Handshake completion < 30s
   - No message replay within window
   - Valid timestamps (+/- 60s)
   - Proper error handling needed for:
     - Failed handshakes
     - Rotation failures
     - Replay attacks

### Scalability Considerations
1. Relay Management
   - Memory-based relay tracking (limitation)
   - 60s heartbeat timeout
   - No persistent storage currently
   - Need monitoring for:
     - Memory usage
     - Connection count
     - Message throughput

2. Dashboard Performance
   - In-memory state management (limitation)
   - Real-time updates via polling
   - No authentication (internal only)
   - Missing:
     - Load testing
     - Performance metrics
     - Resource monitoring

## Future Considerations

### Planned Improvements
1. Authentication System
   - User management
   - Access control
   - Session handling
   - Directory integration (LDAP, Firebase, PKI)
   - Zero-trust and invite-only onboarding

2. Storage Layer
   - Persistent relay state
   - User configurations
   - Access logs
   - Security event logs

3. Monitoring
   - Metrics collection
   - Performance tracking
   - Alert system
   - Security event monitoring

4. Network & DNS
   - IPv6 ULA routing and relay mesh (BGP, overlay)
   - Peer discovery and relay rotation
   - Split DNS, recursive resolver, DNSSEC/blockchain DNS
   - Domain registry (central, git, blockchain/DHT)
   - NAT traversal (TURN/DERP)
   - Overlay routing (Yggdrasil, cjdns)
   - Distributed DNS (DHT-based)

5. Content & Services
   - Internal web, messaging, storage, forums, APIs
   - Content distribution: IPFS/ZeroNet/CDN, offline support
   - App store for internal apps and updates

### Technical Debt
1. Current Limitations
   - In-memory state only
   - No persistent storage
   - Basic authentication
   - Manual relay discovery
   - Limited error handling
   - Missing security event logging
   - Incomplete test coverage

2. Improvement Areas
   - Database integration
   - Service discovery
   - Load balancing
   - Metrics/monitoring
   - Security monitoring
   - Test automation
   - Performance optimization
