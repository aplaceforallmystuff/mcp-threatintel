# MCP Threat Intel Server

[![npm version](https://img.shields.io/npm/v/mcp-threatintel-server.svg)](https://www.npmjs.com/package/mcp-threatintel-server)
[![CI](https://github.com/aplaceforallmystuff/mcp-threatintel/actions/workflows/ci.yml/badge.svg)](https://github.com/aplaceforallmystuff/mcp-threatintel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)

MCP server providing unified access to multiple threat intelligence sources for security research and analysis.

## Why Use This?

If you're doing security research, incident response, or threat analysis, this MCP server lets you:

- **Unified lookups** - Query IPs, domains, hashes, and URLs across multiple sources simultaneously
- **Reduce context switching** - No need to open multiple browser tabs for different intel sources
- **Correlate intelligence** - See results from all configured sources in one response
- **Free tier friendly** - Works with free API tiers, gracefully degrades when sources unavailable
- **Works without keys** - Feodo Tracker (botnet C2s) works without any API keys

## Features

| Category | Capabilities |
|----------|-------------|
| **Unified Lookups** | Query IPs, domains, file hashes, URLs across all sources |
| **AlienVault OTX** | Threat pulses, indicators of compromise, community intelligence |
| **AbuseIPDB** | IP reputation, abuse reports, confidence scores |
| **GreyNoise** | Internet noise vs targeted attacks, scanner identification |
| **abuse.ch** | URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker |

## Prerequisites

- Node.js 18+
- API keys for your preferred threat intelligence sources (see below)

## Installation

### Using npm (Recommended)

```bash
npx mcp-threatintel-server
```

Or install globally:

```bash
npm install -g mcp-threatintel-server
```

### From Source

```bash
git clone https://github.com/aplaceforallmystuff/mcp-threatintel.git
cd mcp-threatintel
npm install
npm run build
```

## Configuration

### For Claude Desktop

Add to your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "npx",
      "args": ["-y", "mcp-threatintel-server"],
      "env": {
        "OTX_API_KEY": "your-otx-api-key",
        "ABUSEIPDB_API_KEY": "your-abuseipdb-api-key",
        "GREYNOISE_API_KEY": "your-greynoise-api-key",
        "ABUSECH_AUTH_KEY": "your-abusech-auth-key"
      }
    }
  }
}
```

### For Claude Code

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "npx",
      "args": ["-y", "mcp-threatintel-server"],
      "env": {
        "OTX_API_KEY": "your-otx-api-key",
        "ABUSEIPDB_API_KEY": "your-abuseipdb-api-key",
        "GREYNOISE_API_KEY": "your-greynoise-api-key",
        "ABUSECH_AUTH_KEY": "your-abusech-auth-key"
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

**Note:** Tools are dynamically enabled based on which API keys you provide. Feodo Tracker works without authentication (public JSON feeds).

## Usage Examples

### Check Available Sources
> "What threat intel sources are configured?"

> "Show me threatintel status"

### IP Investigation
> "Check if 185.220.101.1 is malicious"

> "Look up this IP across all threat intel sources"

### Domain Analysis
> "Is evil-domain.com known to be malicious?"

> "Check domain reputation"

### Malware Hash Lookup
> "Look up this SHA256 hash in threat intel"

> "Is this file hash known malware?"

### URL Analysis
> "Check if this URL is in any blocklists"

### Botnet Tracking (No API Key Required)
> "Show me active botnet C2 servers"

> "Get Feodo tracker data for Emotet"

### Threat Pulses
> "Search OTX for recent ransomware pulses"

> "Get latest threat intelligence pulses"

## Available Tools

### Status
| Tool | Description |
|------|-------------|
| `threatintel_status` | Check which threat intelligence sources are configured |

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

### AlienVault OTX (requires API key)
| Tool | Description |
|------|-------------|
| `otx_get_pulses` | Get recent threat intelligence pulses |
| `otx_search_pulses` | Search pulses by keyword |

### GreyNoise (requires API key)
| Tool | Description |
|------|-------------|
| `greynoise_ip` | Check if IP is internet noise or targeted threat |

### URLhaus (requires abuse.ch auth key)
| Tool | Description |
|------|-------------|
| `urlhaus_lookup` | Look up URL, domain, or IP in URLhaus |
| `urlhaus_recent` | Get recent malware URLs |

### MalwareBazaar (requires abuse.ch auth key)
| Tool | Description |
|------|-------------|
| `malwarebazaar_hash` | Look up malware sample by hash |
| `malwarebazaar_recent` | Get recent malware samples |
| `malwarebazaar_tag` | Search samples by tag |

### ThreatFox (requires abuse.ch auth key)
| Tool | Description |
|------|-------------|
| `threatfox_iocs` | Get recent IOCs from ThreatFox |
| `threatfox_search` | Search ThreatFox IOCs |

### Feodo Tracker (no key required)
| Tool | Description |
|------|-------------|
| `feodo_tracker` | Get active botnet C2 servers (QakBot, Emotet, Dridex, etc.) |

## Development

```bash
# Watch mode for development
npm run watch

# Build TypeScript
npm run build

# Run locally
node dist/index.js
```

## Troubleshooting

### "No threat intel sources configured"
You can use the server without any API keys - Feodo Tracker will still work. For other sources, add the appropriate API keys to your configuration.

### "API error: 401 Unauthorized"
Your API key is invalid or expired. Generate a new one from the respective service.

### "API error: 429 Too Many Requests"
You've exceeded the rate limit for a service. Wait a while or upgrade your API tier.

### Partial results
If some sources return errors, the unified lookup tools will still return results from working sources. Check `threatintel_status` to see which sources are configured correctly.

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

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT - see [LICENSE](LICENSE) for details.

## Links

- [Model Context Protocol](https://modelcontextprotocol.io)
- [MCP Specification](https://spec.modelcontextprotocol.io)
- [GitHub Repository](https://github.com/aplaceforallmystuff/mcp-threatintel)

## Related Projects

For additional threat intelligence capabilities, consider:
- [@burtthecoder/mcp-shodan](https://www.npmjs.com/package/@burtthecoder/mcp-shodan) - Shodan internet scanning
- [@burtthecoder/mcp-virustotal](https://www.npmjs.com/package/@burtthecoder/mcp-virustotal) - VirusTotal malware analysis
