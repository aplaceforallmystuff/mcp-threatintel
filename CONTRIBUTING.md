# Contributing to mcp-threatintel

Thank you for your interest in contributing to mcp-threatintel!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/aplaceforallmystuff/mcp-threatintel.git
cd mcp-threatintel
```

2. Install dependencies:
```bash
npm install
```

3. Build:
```bash
npm run build
```

4. Test locally by adding to your MCP config:
```json
{
  "mcpServers": {
    "threatintel-dev": {
      "command": "node",
      "args": ["/path/to/mcp-threatintel/dist/index.js"],
      "env": {
        "OTX_API_KEY": "your-key"
      }
    }
  }
}
```

## Adding New Threat Intelligence Sources

When adding a new data source:

1. Add API client functions in `src/index.ts`
2. Register tools with appropriate input schemas
3. Consider whether the source requires authentication
4. Add documentation to README.md
5. Test thoroughly before submitting PR

## Code Style

- TypeScript with strict mode
- ES modules (ESM)
- Async/await for all API calls
- Proper error handling with informative messages

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with actual API calls where possible
5. Update documentation
6. Submit PR with clear description

## Reporting Issues

Please include:
- Description of the issue
- Steps to reproduce
- Expected vs actual behavior
- API source involved (if applicable)
- Any error messages

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
