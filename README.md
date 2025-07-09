# DNSGapHunter

A comprehensive tool designed to test the effectiveness of DNS security solutions (DNS Firewall, Sinkhole, etc.). This tool evaluates how successfully DNS security solutions block malicious domains by testing them against domains collected from various threat intelligence sources.

## Features

- Support for multiple threat intelligence sources
- DNS Firewall and Sinkhole testing capabilities
- Fast analysis with parallel DNS queries
- Detailed HTML reporting
- Support for various domain formats (URL, hostfile, CSV, etc.)
- Comprehensive domain filtering and validation

## Installation

1. Install Python 3.8 or higher
2. Clone the repository:
```bash
git clone https://github.com/yourusername/DNSGapHunter.git
cd DNSGapHunter
```

3. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

4. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

To run the tool:

```bash
python DNSGapHunter.py
```

### Security Configuration

The tool offers 4 different security configurations:

1. DNS Firewall (Infoblox Threat Defense)
2. DNS Firewall (Manual IP entry)
3. DNS Firewall (IP list file)
4. Sinkhole DNS Security

### Outputs

When run, the program generates the following outputs:

- DNS query results (CSV)
- Domains with no DNS records (CSV)
- Filtered domains (CSV)
- Detailed HTML report

## Threat Intelligence Sources

- ThreatFox (abuse.ch)
- URLhaus (abuse.ch)
- OpenPhish
- CyberCrime
- Botvrij
- StopForumSpam
- PhishingArmy

## Configuration

You can customize the following settings in `config.py`:

- DNS timeout duration
- DNS retry count
- Maximum domain count
- Thread count
- Whitelist domains
- Report directories

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork this repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Create a Pull Request
