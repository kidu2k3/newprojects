# System Architecture & Design Patterns

## Overall Architecture

### Network Architecture
- Chain-based relay system
- Multi-hop message routing
- Encrypted communication channels
- Basic heartbeat monitoring

### Core Components
1. Client Component
   - Async connection management
   - Chain establishment
   - File transfer system
   - Relay discovery

2. Relay Component
   - Message forwarding
   - Chain routing
   - Fake traffic generation
   - Connection handling

3. Dashboard Component
   - Relay registration
   - Status monitoring 
   - Basic metrics tracking
   - Web interface

## Component Architecture

### Frontend (overnet-client)
```
overnet-client/
├── src/
│   ├── components/
│   │   └── TLDsDashboard.jsx  # Main dashboard component
│   └── App.jsx                # Main application with routing
└── dist/                      # Production build
```

- React-based architecture
- Component-based design
- Responsive layout with Tailwind CSS
- Real-time data integration patterns
- Professional UI components (shadcn/ui)
- Tabbed interface architecture

### Backend (overnet-tld-server)
```
overnet-tld-server/
├── src/
│   ├── routes/
│   │   └── dashboard.py       # Dashboard API endpoints
│   └── main.py               # Core server with dashboard integration
└── requirements.txt
```

- Blueprint-based API organization
- RESTful endpoint design
- Real-time monitoring patterns
- Database integration patterns

### Relay Server Integration
```
overnet-relay-server/         # Core relay functionality
```
- Server status monitoring patterns
- Connection tracking design
- Performance metric collection
- Health check implementation

## Design Patterns

### Core Patterns
- Async Communication (asyncio)
- Chain-based Message Routing
- Handshake Protocol
- Encrypted Message Exchange

### Client Patterns
- Dynamic Relay Selection
- Multi-hop Chain Building
- File Chunking for Transfers
- Command-line Interface Design

### Relay Patterns
- Message Forwarding Logic
- Connection State Management
- Traffic Obfuscation
- Heartbeat Implementation

### Dashboard Patterns
- Flask Blueprint Structure
- Simple Template Rendering
- Basic State Management
- HTTP API Design

## Communication Patterns

### Network Protocol
- Handshake-based Connection Setup
- Encrypted Message Exchange
- Chain-based Routing
- Basic Health Checks

### API Design
- Simple REST Endpoints
- Relay Registration
- Status Updates
- Basic Metrics

## Implementation Details

### Client Features
- Relay discovery via dashboard
- Chain-based connections
- File transfer capability
- Basic ping functionality
- Virtual interface creation

### Relay Features
- Message forwarding
- Chain routing
- Connection handling
- Fake traffic generation
- Status reporting

### Dashboard Features
- Relay registration
- Active relay listing
- Basic status tracking
- Simple web interface
- Metrics endpoint
