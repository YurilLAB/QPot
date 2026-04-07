# QPot Development Guidelines

## Core Principles

### 1. Edit Existing Files - Do Not Create Duplicates
- **ALWAYS** edit existing files when making improvements
- **NEVER** create files named: `improved_`, `enhanced_`, `v2_`, `v1_`, `new_`, `better_`
- **NEVER** create duplicate files with slightly different names
- If a file exists, modify it. If functionality needs to change, refactor the existing code.

### 2. No Placeholders or Stubs
- **ONLY** implement fully working, tested, and connected features
- **NEVER** create:
  - `TODO` comments with no implementation
  - Empty function stubs
  - Placeholder files
  - "Coming soon" features
  - Partial implementations
- If you start a feature, finish it completely before committing

### 3. Language Requirements
- **ALL implementation code must be in C or Go**
- Shell scripts only for bootstrapping/installation
- Python only if absolutely necessary for existing honeypot integration
- No JavaScript/Node.js for backend

### 4. Safety-First Architecture
QPot must be safe to run on personal computers:
- All honeypots run in isolated containers (no host network mode)
- Rootless container execution where possible
- Resource limits (CPU, memory, disk) on all services
- Read-only filesystems for honeypot containers
- No privileged containers for honeypots
- gVisor or Kata Containers for high-risk honeypots
- Automatic container restart limits
- Network segregation between honeypots

### 5. Multi-Instance Support
Users can run multiple QPot instances:
- Dynamic port allocation to avoid conflicts
- Instance naming/identification
- Separate data directories per instance
- Easy instance management (create, start, stop, remove)

### 6. Database Flexibility
Support multiple backends:
- ClickHouse (columnar, fast analytics)
- TimescaleDB (PostgreSQL-compatible time-series)
- Keep Elastic Stack as optional legacy support
- Abstract data layer to switch between them

### 7. User-Friendly Design
- One-command setup (`qpot up`)
- Web UI for configuration (Go-based backend)
- Clear status indicators (which honeypots are running)
- Easy log viewing without complex queries
- Automatic updates with safety checks

## Project Structure

```
QPot/
├── cmd/qpot/                   # Main CLI entry point (Go)
├── internal/                   # Private Go packages
│   ├── config/                 # Configuration management
│   ├── database/               # Database abstraction (ClickHouse, TimescaleDB)
│   ├── honeypots/              # Honeypot management
│   ├── security/               # Sandboxing and isolation
│   ├── server/                 # Web API server
│   └── instance/               # Multi-instance management
├── pkg/                        # Public Go packages
├── docker/                     # Docker configurations
├── web/                        # Static web UI files
├── scripts/                    # Install/update scripts
└── docs/
```

## Coding Standards (Go)

1. **Standard Go project layout**
2. **All public functions documented**
3. **Context-based cancellation**
4. **Structured logging (slog)**
5. **Error wrapping with fmt.Errorf**
6. **Security review for any network-facing code**
7. **Race detection in tests**

## Coding Standards (C)

1. **C11 standard**
2. **All memory allocations checked**
3. **No unsafe string functions (strcpy, sprintf)**
4. **Use strncpy, snprintf with bounds checking**
5. **Valgrind clean**
6. **Static analysis with clang-analyzer**
