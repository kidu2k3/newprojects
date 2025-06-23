# Product Context

## User Needs
- Private, secure alternative to traditional internet
- Self-hosted services and content
- Control over routing and domain naming
- Easy-to-use client interface for network access
- Seamless peer discovery and relay selection
- Support for internal-only apps (web, messaging, storage, forums, etc.)
- App store for internal apps and updates
- Offline content access and distributed storage
- Fine-grained access control (per-user, per-domain, per-app)
- Invite-only or referral-based onboarding

## Core Requirements

### Network Security
- End-to-end encryption via WireGuard and Noise Protocol
- Key rotation and replay protection
- Secure handshake protocol
- Private addressing using IPv6 ULA space
- Zero-trust access controls (per-app WG keys)
- Directory/auth server integration (LDAP, Firebase, PKI)
- Invite-only/referral join process

### Network Infrastructure 
- Relay mesh network for traffic routing (full mesh, multi-hop, BGP)
- IPv6 ULA addressing and routing (fc00::/7)
- Peer discovery and relay rotation
- Internal DNS for .alt and similar domains (authoritative and recursive)
- Split DNS for internal/external domains
- DNSSEC and blockchain-based DNS (Handshake/Namecoin)
- Domain registry for .alt (central, git, blockchain/DHT)
- Dashboard for relay and DNS management
- Client application for user access (Tauri/Electron GUI)
- NAT traversal (TURN/DERP)
- Overlay routing (Yggdrasil, cjdns)
- Distributed DNS (DHT-based)

### Service Architecture
- Support for internal web, messaging, storage, forums, and API services
- Content distribution: IPFS/ZeroNet/CDN, offline support
- App store for internal apps and updates
- Access control and authentication
- Per-user/domain/subnet permissions
- Audit logging and monitoring
## Success Criteria
1. Secure Communications
   - All traffic encrypted end-to-end
   - No unauthorized access possible
   - Protection against replay attacks

2. Network Reliability
   - Stable relay connections
   - Automatic key rotation
   - Heartbeat monitoring

3. Usability
   - Simple client setup process
   - Clear relay status dashboard
   - Easy service deployment

4. Scalability
   - Support for multiple relays
   - Distributed content hosting
   - Extensible for future services
