# Technical Context & Stack

## Core Technologies

### Primary Stack
- Python (Core implementation language)
- Flask web framework
- Asyncio for async operations
- Aiohttp for async HTTP

### Project Components
- Client module (Python-based)
  - Async client implementation
  - Connection management
  - Relay chain setup
  - File transfer capabilities
  
- Dashboard module (Python/Flask)
  - Relay registration
  - Heartbeat monitoring
  - Basic status tracking
  - Simple web interface
  
- Relay module (Python-based)
  - Async relay server
  - Message forwarding
  - Handshake protocol
  - Fake traffic generation

## Project Structure
```
/
├── client/               # Client implementation
│   ├── __init__.py
│   ├── client.py
│   └── dashboard_app.py
├── dashboard/           # Dashboard implementation
│   ├── __init__.py
│   ├── dashboard.py
│   └── templates/
│       └── index.html
├── relay/              # Relay server implementation
│   ├── __init__.py
│   └── relay.py
├── scripts/            # Management scripts
│   ├── start_client_dashboard.py
│   ├── start_relay_with_dashboard.py
│   └── start_relay.py
├── tests/             # Test suite
│   ├── __init__.py
│   ├── test_handshake.py
│   └── test_integration.py
├── requirements.txt    # Production dependencies
└── requirements-dev.txt # Development dependencies
```

## Development Environment

### Prerequisites
- Python environment
- pip package manager
- Git version control

### Dependencies
- Production requirements: requirements.txt
- Development requirements: requirements-dev.txt

## Infrastructure

### Production Deployment
- Live TLD Server: https://p9hwiqc538k0.manus.space
- Relay Server: https://58hpi8clvo93.manus.space
- Frontend Client: https://yxtufqnd.manus.space

### Network Infrastructure
- WireGuard VPN integration
- IPv6 overlay network
- Multi-server relay architecture
- Load balancing system

## Component Architecture

### Client Module
- Core client functionality
- Dashboard app integration
- Network communication handling

### Dashboard Module
- Web interface implementation
- Template-based rendering
- Status monitoring interface

### Relay Module
- Relay server implementation
- Connection management
- Network routing

## Testing Infrastructure
- Python unittest framework
- Integration tests
- Handshake testing
- Test coverage tracking

## Security Implementation
- WireGuard encryption
- Secure key exchange
- Access control system
- IPv6 networking security

## Performance Characteristics
- Real-time update capability
- Low-latency communication
- Efficient data handling
- Network optimization

## Monitoring & Metrics
- Server health tracking
- Client connection monitoring
- Performance analytics
- Network diagnostics

## Scripts & Tools
- Client dashboard startup
- Relay server management
- Development utilities

## Version Control
- Git-based workflow
- Feature branch strategy
- Version tagging
- Release management

## Documentation
- Code documentation
- Setup guides
- Testing procedures
- Deployment instructions
