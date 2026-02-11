# CLAUDE.md - mcp-threatintel

MCP server for unified threat intelligence across multiple sources (OTX, AbuseIPDB, GreyNoise, abuse.ch).

## Tech Stack

- **Language:** TypeScript
- **Runtime:** Node.js (ES modules)
- **Protocol:** Model Context Protocol (MCP)
- **Build:** TypeScript compiler (tsc)

## Architecture

```
src/
  index.ts          # Server, multi-source config, dynamic tool registration, all handlers
```

## Development Commands

```bash
npm run build       # tsc
npm run watch       # tsc --watch
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OTX_API_KEY` | No | AlienVault OTX API key |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key |
| `GREYNOISE_API_KEY` | No | GreyNoise API key |
| `ABUSECH_AUTH_KEY` | No | abuse.ch auth key (URLhaus, MalwareBazaar, ThreatFox) |

## Tools (up to 17, dynamic based on which keys are set)

**Always available:** `threatintel_status`, `threatintel_lookup_ip`, `threatintel_lookup_domain`, `threatintel_lookup_hash`, `threatintel_lookup_url`, `feodo_tracker`
**With AbuseIPDB key:** `abuseipdb_check`
**With OTX key:** `otx_get_pulses`, `otx_search_pulses`
**With GreyNoise key:** `greynoise_ip`
**With abuse.ch key:** `urlhaus_lookup`, `urlhaus_recent`, `malwarebazaar_hash`, `malwarebazaar_recent`, `malwarebazaar_tag`, `threatfox_iocs`, `threatfox_search`

## Key Patterns

- Uses `Server` class from MCP SDK (low-level API with `setRequestHandler`)
- **Dynamic tool registration**: tools added to `TOOLS` array based on which API keys are present
- Unified lookups query all configured sources, catch per-source errors, return partial results
- `apiRequest<T>()` generic helper for all external API calls
- No keys required to start (warns but continues with available sources)
