# Security Policy

## Reporting a Vulnerability

If you discover a security issue, please report it privately rather than opening a public GitHub issue. Email: **hello@jimchristian.net**.

Include where you can:

- A description of the issue and its potential impact
- Steps to reproduce
- Affected version(s)
- Any suggested mitigation

You can expect an acknowledgement within 7 days. I'll work with you on a coordinated disclosure timeline before any public write-up.

## Supported Versions

Only the latest published version on npm is actively supported with security fixes. Older versions may receive backports at my discretion.

## Scope

In scope:
- Bugs in this MCP server's code that lead to credential exposure, unauthorized access, or remote code execution
- Vulnerabilities introduced by direct dependencies that affect this server's runtime

Out of scope:
- Vulnerabilities in the upstream APIs this server wraps (please report those to the upstream vendor)
- Theoretical issues without a practical exploit path
