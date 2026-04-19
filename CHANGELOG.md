# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.3] - 2026-04-19

### Fixed
- **MalwareBazaar + ThreatFox silently returned empty responses.** The API base URLs `https://mb-api.abuse.ch/api/v1` and `https://threatfox-api.abuse.ch/api/v1` 301-redirect when hit without a trailing slash, and `fetch`/`curl` drop the POST body on redirect. Every MalwareBazaar and ThreatFox call was affected. Fixed by adding the trailing slash to the base URL constants.

### Changed
- **GreyNoise now works without an API key.** The community endpoint (`/v3/community/{ip}`) is accessible without auth; the key, when set, is still sent as a header for higher rate limits. Previously the tool was disabled entirely when `GREYNOISE_API_KEY` was unset.
- Updated environment variable documentation to reflect `GREYNOISE_API_KEY` being optional and `ABUSECH_AUTH_KEY` being required for URLhaus/MalwareBazaar/ThreatFox.

## [1.0.2] - 2025-12-20

### Changed
- Updated @modelcontextprotocol/sdk to ^1.25.1 (security fix)
- Expanded package keywords for npm discoverability
- Added homepage and bugs URLs to package.json
- Fixed repository URL format

## [1.0.1] - 2025-11-28

### Added
- MCP registry support with `server.json`
- Badges to README (npm version, MIT license, Node.js version)
- Authentication support for abuse.ch APIs via `ABUSECH_AUTH_KEY`

### Changed
- abuse.ch APIs (URLhaus, MalwareBazaar, ThreatFox) now require Auth-Key
- Tools dynamically enabled based on configured API keys
- Updated README with accurate tool names and auth requirements

### Fixed
- Binary path in package.json
- Tool names in documentation to match implementation
- Clarified that Feodo Tracker works with public JSON feeds (no auth required)

## [1.0.0] - 2025-11-28

### Added
- Initial release with unified threat intelligence MCP server
- **Unified lookup tools:**
  - `threatintel_lookup_ip` - Query IP across all configured sources
  - `threatintel_lookup_domain` - Query domain across all sources
  - `threatintel_lookup_hash` - Query file hash across all sources
  - `threatintel_lookup_url` - Query URL across all sources
  - `threatintel_status` - Check which services are configured
- **AlienVault OTX integration:**
  - Pulse and indicator lookups
  - Requires `OTX_API_KEY`
- **AbuseIPDB integration:**
  - IP reputation checking
  - Requires `ABUSEIPDB_API_KEY`
- **GreyNoise integration:**
  - Distinguish noise from targeted threats
  - Requires `GREYNOISE_API_KEY`
- **abuse.ch feeds:**
  - URLhaus - Malicious URL database
  - MalwareBazaar - Malware sample database
  - ThreatFox - IOC sharing platform
  - Feodo Tracker - Botnet C2 tracking (public feeds, no auth required)
- Dynamic tool registration based on configured API keys
