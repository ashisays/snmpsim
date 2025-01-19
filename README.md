# SNMP Simulator with Raw Socket Support

A high-performance SNMP simulator that uses raw sockets to respond to SNMP requests. This simulator can handle SNMPv1, SNMPv2c, and SNMPv3 requests across multiple IP ranges.

## Features

- Raw socket implementation for high performance
- Support for SNMPv1, SNMPv2c, and SNMPv3
- Multiple IP range support
- CSV-based response configuration
- YAML-based server configuration
- Dynamic MAC address generation
- Support for value ranges and lists in responses
- Comprehensive test coverage
- GitHub Actions CI/CD integration

## Prerequisites

- Python 3.8 or higher
- Root/Administrator privileges (required for raw sockets)
- Linux/Unix environment (Windows support limited due to raw socket implementation)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/snmp-simulator.git
cd snmp-simulator
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

### Server Configuration (config.yaml)

```yaml
snmp:
  community: public
  versions: [1, 2c, 3]
  v3:
    username: admin
    auth_key: authpassword
    priv_key: privpassword
    security_level: authPriv
    auth_protocol: MD5
    priv_protocol: DES

listen:
  port: 161
  ip_ranges:
    - ip: 192.168.1.0/24
      description: Local network
    - ip: 10.0.0.0/8
      description: Corporate network
```

### Response Configuration (data.csv)

Create a CSV file with the following fields:
```csv
iprange,macprefix,sysDesc,sysObjectID,sysContact,sysName,sysLocation,hrDeviceType,...
```

Supported value formats:
- Static values: `"Single Value"`
- Multiple values: `"Value1;Value2;Value3"`
- Ranges: `"Value1-Value10"`
- Dynamic MAC addresses: `"00:11:22:$$"` (where $$ is dynamically replaced)

## Usage

1. Start the SNMP simulator (requires root privileges):
```bash
sudo python snmp_server.py
```

2. The server will listen on the configured IP ranges and port for SNMP requests.

3. Testing the server:
```bash
# Using snmpwalk (SNMPv1)
snmpwalk -v1 -c public 192.168.1.1

# Using snmpwalk (SNMPv2c)
snmpwalk -v2c -c public 192.168.1.1

# Using snmpwalk (SNMPv3)
snmpwalk -v3 -u admin -l authPriv -a MD5 -A authpassword -x DES -X privpassword 192.168.1.1
```

## Development

### Running Tests

1. Run unit tests:
```bash
pytest tests/
```

2. Run integration tests (requires root privileges):
```bash
sudo pytest integration_tests/
```

3. Run tests with coverage:
```bash
pytest --cov=. tests/ integration_tests/
```

### Code Style

The project uses:
- Black for code formatting
- Pylint for code linting

Format code:
```bash
black .
```

Run linting:
```bash
pylint snmp_server.py
```

## GitHub Actions

The project includes GitHub Actions workflows for:
- Dependency installation
- Code linting
- Unit testing
- Integration testing
- Coverage reporting

## Project Structure

```
.
├── .github
│   └── workflows
│       └── ci.yml
├── tests
│   └── test_snmp_server.py
├── integration_tests
│   └── test_snmp_server.py
├── config.yaml
├── data.csv
├── requirements.txt
├── README.md
└── snmp_server.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security Considerations

- The simulator uses raw sockets and requires root privileges
- Configure firewall rules appropriately
- Use strong passwords for SNMPv3
- Limit access to authorized IP ranges

## Known Limitations

- Raw socket implementation requires root privileges
- Limited Windows support due to raw socket implementation
- Some SNMP operations might not be fully implemented
- Performance may vary based on system resources

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The SNMP protocol specification (RFC 1157)
- Python's socket library documentation
- Community contributions and feedback

## Support

For issues and feature requests, please use the GitHub issue tracker.
