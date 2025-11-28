# mcp-threatintel

MCP server providing unified access to multiple threat intelligence sources for security research and analysis.

## Features

- **Unified lookups** - Query IP addresses, domains, file hashes, and URLs across multiple sources simultaneously
- **AlienVault OTX** - Access Open Threat Exchange pulses and indicators
- **AbuseIPDB** - IP reputation and abuse reports
- **GreyNoise** - Internet scanner and noise identification
- **abuse.ch feeds** - URLhaus, MalwareBazaar, ThreatFox, and Feodo Tracker

## Installation

```bash
npm install -g mcp-threatintel-server
```

## Configuration

Add to your Claude Desktop or Claude Code MCP settings:

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "mcp-threatintel",
      "env": {
        "OTX_API_KEY": "your-otx-api-key",
        "ABUSEIPDB_API_KEY": "your-abuseipdb-api-key",
        "GREYNOISE_API_KEY": "your-greynoise-api-key"
      }
    }
  }
}
```

### API Keys

| Service | Required | Free Tier | Get Key |
|---------|----------|-----------|---------|
| AlienVault OTX | Optional | Yes (unlimited) | [otx.alienvault.com](https://otx.alienvault.com) |
| AbuseIPDB | Optional | Yes (1,000/day) | [abuseipdb.com](https://www.abuseipdb.com) |
| GreyNoise | Optional | Yes (limited) | [greynoise.io](https://www.greynoise.io) |
| abuse.ch | Optional | Yes | [auth.abuse.ch](https://auth.abuse.ch) |
| Feodo Tracker | No | Yes | Public JSON feeds |

**Note:** Most tools are dynamically enabled based on which API keys you provide. Feodo Tracker works without authentication (public JSON feeds). As of late 2024, abuse.ch APIs (URLhaus, MalwareBazaar, ThreatFox) require authentication.

## Tools

### Unified Lookups

| Tool | Description |
|------|-------------|
| `threatintel_lookup_ip` | Look up IP across all configured sources |
| `threatintel_lookup_domain` | Look up domain across all configured sources |
| `threatintel_lookup_hash` | Look up file hash (MD5/SHA1/SHA256) across sources |
| `threatintel_lookup_url` | Look up URL across sources |

### AbuseIPDB (requires API key)

| Tool | Description |
|------|-------------|
| `abuseipdb_check` | Check IP reputation and abuse history |
| `abuseipdb_reports` | Get detailed abuse reports for an IP |

### AlienVault OTX (requires API key)

| Tool | Description |
|------|-------------|
| `otx_indicator` | Get OTX indicator details |
| `otx_pulses` | Search OTX pulses |

### GreyNoise (requires API key)

| Tool | Description |
|------|-------------|
| `greynoise_ip` | Check if IP is internet noise or targeted threat |
| `greynoise_quick` | Quick noise check for IP |

### URLhaus (no key required)

| Tool | Description |
|------|-------------|
| `urlhaus_lookup` | Look up URL, domain, or IP in URLhaus |
| `urlhaus_recent` | Get recent malware URLs |

### MalwareBazaar (no key required)

| Tool | Description |
|------|-------------|
| `malwarebazaar_hash` | Look up malware sample by hash |
| `malwarebazaar_recent` | Get recent malware samples |
| `malwarebazaar_tag` | Search samples by tag |

### ThreatFox (no key required)

| Tool | Description |
|------|-------------|
| `threatfox_iocs` | Get recent IOCs from ThreatFox |
| `threatfox_search` | Search ThreatFox IOCs |

### Feodo Tracker (no key required)

| Tool | Description |
|------|-------------|
| `feodo_tracker` | Get Feodo/Emotet/Dridex botnet C2 servers |

## Usage Examples

### Check a suspicious IP
```
Use threatintel_lookup_ip to check 185.220.101.1
```

### Look up a malware hash
```
Use malwarebazaar_hash to look up 44d88612fea8a8f36de82e1278abb02f
```

### Get recent malware URLs
```
Use urlhaus_recent to get the latest 25 malware distribution URLs
```

### Search for Emotet IOCs
```
Use threatfox_search to find IOCs tagged "emotet"
```

## Data Sources

### AlienVault OTX
Open Threat Exchange - community-driven threat intelligence platform with pulses containing indicators of compromise.

### AbuseIPDB
Crowdsourced IP reputation database with abuse reports from network administrators worldwide.

### GreyNoise
Identifies IPs scanning the internet vs targeted attacks. Helps reduce false positives in threat detection.

### abuse.ch Projects
- **URLhaus** - Malware distribution URLs
- **MalwareBazaar** - Malware sample repository
- **ThreatFox** - IOC sharing platform
- **Feodo Tracker** - Botnet C2 infrastructure tracking

## License

MIT

## Author

Jim Christian

## Related Projects

For additional threat intelligence capabilities, consider:
- [@burtthecoder/mcp-shodan](https://www.npmjs.com/package/@burtthecoder/mcp-shodan) - Shodan internet scanning
- [@burtthecoder/mcp-virustotal](https://www.npmjs.com/package/@burtthecoder/mcp-virustotal) - VirusTotal malware analysis
