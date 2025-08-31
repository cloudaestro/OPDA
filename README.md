# OPDA - Okta Privilege Drift Auditor

[![CI](https://github.com/company/opda/workflows/CI/badge.svg)](https://github.com/company/opda/actions)
[![Coverage](https://codecov.io/gh/company/opda/branch/main/graph/badge.svg)](https://codecov.io/gh/company/opda)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Enterprise-grade IAM security auditing tool that detects privilege drift in Okta environments using policy-as-code approach.

## Features

- **🔍 Comprehensive Auditing**: Scans users, groups, applications, roles, and system logs
- **📏 Policy-Driven**: Uses Rego policies for RBAC, ABAC, and temporal compliance rules
- **📊 Rich Reporting**: Interactive HTML dashboards, signed PDF reports, CSV/JSON exports
- **🔧 Smart Remediation**: Direct API fixes or Okta Workflows integration with approval workflows
- **🐳 Container-Ready**: Single Docker image, fully offline operation
- **⚡ Production-Grade**: Rate limiting, pagination, async I/O, comprehensive logging

## Quick Start

### Docker (Recommended)

```bash
# Pull the latest image
docker pull ghcr.io/company/opda:latest

# Run audit with environment variables
docker run -e OKTA_DOMAIN=mycompany.okta.com \
           -e OKTA_TOKEN=your-api-token \
           -v $(pwd)/reports:/app/reports \
           ghcr.io/company/opda:latest audit --output-dir /app/reports

# View the generated dashboard
open reports/audit-dashboard.html
```

### Local Installation

```bash
# Install from PyPI
pip install opda

# Or install from source
git clone https://github.com/company/opda.git
cd opda
pip install -e .[dev]

# Run audit
export OKTA_DOMAIN="mycompany.okta.com"
export OKTA_TOKEN="your-api-token"
opda audit --output-dir ./reports
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OKTA_DOMAIN` | Yes | Your Okta domain (e.g., `company.okta.com`) |
| `OKTA_TOKEN` | Yes | Okta API token with read permissions |
| `OPDA_LOG_LEVEL` | No | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |
| `OPDA_POLICIES_DIR` | No | Custom policies directory (default: `./policies`) |
| `OPDA_OUTPUT_DIR` | No | Report output directory (default: `./reports`) |

### Policy Configuration

Place your custom Rego policies in the `policies/` directory:

```
policies/
├── rbac/
│   ├── admin_roles.rego
│   └── user_permissions.rego
├── abac/
│   ├── context_based.rego
│   └── attribute_checks.rego
└── temporal/
    ├── session_limits.rego
    └── access_review.rego
```

## Usage Examples

### Basic Audit
```bash
# Run complete audit with default settings
opda audit

# Audit specific components
opda audit --users --groups --skip-apps

# Custom policy directory
opda audit --policies-dir ./custom-policies
```

### Report Generation
```bash
# Generate all report formats
opda report --format html,pdf,json,csv

# PDF with digital signature
opda report --format pdf --sign --cert ./signing.p12

# Custom template
opda report --template ./custom-dashboard.html
```

### Remediation
```bash
# Show remediation recommendations only
opda remediate --dry-run

# Apply fixes directly via API
opda remediate --apply --confirm

# Create Okta Workflows tasks for approval
opda remediate --workflows --approver john.doe@company.com
```

## Architecture

OPDA follows a modular architecture with clear separation of concerns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │────│  Core Engine    │────│ Report Generator│
│   (Typer)      │    │  (Async)        │    │ (HTML/PDF/CSV)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Okta Client    │    │ Policy Engine   │    │ Remediation     │
│  (Rate Limited) │    │ (OPA/Rego)      │    │ (API/Workflows) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Data Models     │
                    │ (Pydantic)      │
                    └─────────────────┘
```

## Development

### Prerequisites
- Python 3.12+
- Docker (for containerized development)
- OPA binary (for policy testing)

### Setup Development Environment
```bash
git clone https://github.com/company/opda.git
cd opda

# Install development dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run linting
ruff check .
mypy .
```

### Running Tests
```bash
# Unit tests only
pytest -m "not integration"

# Integration tests (requires Okta sandbox)
export OKTA_TEST_DOMAIN="dev.okta.com"
export OKTA_TEST_TOKEN="test-token"
pytest -m integration

# Coverage report
pytest --cov --cov-report=html
open htmlcov/index.html
```

## Security Considerations

- **API Tokens**: Store Okta tokens securely, use read-only permissions
- **Network Access**: OPDA requires outbound HTTPS to your Okta domain
- **Data Storage**: Audit data is stored locally in SQLite, encrypt sensitive environments
- **PDF Signatures**: Use hardware security modules (HSM) for production PDF signing

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests and documentation
4. Run quality checks (`ruff check . && mypy . && pytest`)
5. Commit your changes (`git commit -m 'feat: add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/company/opda/issues)
- **Discussions**: [GitHub Discussions](https://github.com/company/opda/discussions)
- **Security**: Report vulnerabilities to security@company.com

---

**OPDA** - Keeping your Okta environment secure, one audit at a time. 🔐