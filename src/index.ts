#!/usr/bin/env node
/**
 * MCP Server for Unified Threat Intelligence
 *
 * Aggregates data from multiple free threat intel sources:
 * - AlienVault OTX (IOCs, pulses, campaigns)
 * - AbuseIPDB (IP reputation)
 * - GreyNoise (noise vs threat classification)
 * - abuse.ch feeds (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker)
 *
 * Environment variables:
 * - OTX_API_KEY: AlienVault OTX API key (free at otx.alienvault.com)
 * - ABUSEIPDB_API_KEY: AbuseIPDB API key (free at abuseipdb.com)
 * - GREYNOISE_API_KEY: GreyNoise API key (free community tier)
 * - ABUSECH_AUTH_KEY: abuse.ch auth key (free at auth.abuse.ch) - optional
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

// API Configuration
const config = {
  otx: {
    apiKey: process.env.OTX_API_KEY,
    baseUrl: "https://otx.alienvault.com/api/v1",
  },
  abuseipdb: {
    apiKey: process.env.ABUSEIPDB_API_KEY,
    baseUrl: "https://api.abuseipdb.com/api/v2",
  },
  greynoise: {
    apiKey: process.env.GREYNOISE_API_KEY,
    baseUrl: "https://api.greynoise.io/v3",
  },
  abusech: {
    authKey: process.env.ABUSECH_AUTH_KEY,
    urlhaus: "https://urlhaus-api.abuse.ch/v1",
    malwarebazaar: "https://mb-api.abuse.ch/api/v1",
    threatfox: "https://threatfox-api.abuse.ch/api/v1",
    feodo: "https://feodotracker.abuse.ch/downloads",
  },
};

// Track which services are configured
const services = {
  otx: !!config.otx.apiKey,
  abuseipdb: !!config.abuseipdb.apiKey,
  greynoise: !!config.greynoise.apiKey,
  abusech: true, // abuse.ch works without auth for most queries
};

const configuredServices = Object.entries(services)
  .filter(([, enabled]) => enabled)
  .map(([name]) => name);

if (configuredServices.length === 0) {
  console.error("Warning: No API keys configured. Some features will be limited.");
  console.error("Set OTX_API_KEY, ABUSEIPDB_API_KEY, and/or GREYNOISE_API_KEY for full functionality.");
}

// Helper function for API requests
async function apiRequest<T>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API error ${response.status}: ${text}`);
  }

  return response.json() as Promise<T>;
}

// Define available tools
const TOOLS: Tool[] = [
  // Status tool
  {
    name: "threatintel_status",
    description: `Check which threat intelligence sources are configured. Currently available: ${configuredServices.join(", ") || "none (abuse.ch feeds work without auth)"}`,
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  // Unified lookup
  {
    name: "threatintel_lookup_ip",
    description: "Look up an IP address across all configured threat intelligence sources (OTX, AbuseIPDB, GreyNoise, Feodo Tracker)",
    inputSchema: {
      type: "object" as const,
      properties: {
        ip: {
          type: "string",
          description: "IP address to look up",
        },
      },
      required: ["ip"],
    },
  },
  {
    name: "threatintel_lookup_domain",
    description: "Look up a domain across threat intelligence sources (OTX, URLhaus)",
    inputSchema: {
      type: "object" as const,
      properties: {
        domain: {
          type: "string",
          description: "Domain name to look up",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "threatintel_lookup_hash",
    description: "Look up a file hash (MD5, SHA1, SHA256) across threat intelligence sources (OTX, MalwareBazaar)",
    inputSchema: {
      type: "object" as const,
      properties: {
        hash: {
          type: "string",
          description: "File hash (MD5, SHA1, or SHA256)",
        },
      },
      required: ["hash"],
    },
  },
  {
    name: "threatintel_lookup_url",
    description: "Look up a URL for malware/phishing indicators (OTX, URLhaus)",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "URL to check",
        },
      },
      required: ["url"],
    },
  },
];

// AbuseIPDB tools
if (services.abuseipdb) {
  TOOLS.push({
    name: "abuseipdb_check",
    description: "Check IP reputation on AbuseIPDB - returns abuse confidence score and recent reports",
    inputSchema: {
      type: "object" as const,
      properties: {
        ip: {
          type: "string",
          description: "IP address to check",
        },
        maxAgeInDays: {
          type: "number",
          description: "How far back to check (default: 90, max: 365)",
        },
      },
      required: ["ip"],
    },
  });
}

// OTX tools
if (services.otx) {
  TOOLS.push(
    {
      name: "otx_get_pulses",
      description: "Get recent threat intelligence pulses from AlienVault OTX",
      inputSchema: {
        type: "object" as const,
        properties: {
          limit: {
            type: "number",
            description: "Number of pulses to retrieve (default: 10)",
          },
        },
        required: [],
      },
    },
    {
      name: "otx_search_pulses",
      description: "Search OTX pulses by keyword (malware name, campaign, threat actor)",
      inputSchema: {
        type: "object" as const,
        properties: {
          query: {
            type: "string",
            description: "Search query (e.g., 'emotet', 'apt29', 'ransomware')",
          },
        },
        required: ["query"],
      },
    }
  );
}

// GreyNoise tools
if (services.greynoise) {
  TOOLS.push({
    name: "greynoise_ip",
    description: "Check if an IP is internet background noise or a targeted threat (GreyNoise)",
    inputSchema: {
      type: "object" as const,
      properties: {
        ip: {
          type: "string",
          description: "IP address to check",
        },
      },
      required: ["ip"],
    },
  });
}

// abuse.ch tools (work without auth)
TOOLS.push(
  {
    name: "urlhaus_lookup",
    description: "Check if a URL or domain is distributing malware (URLhaus)",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "URL or domain to check",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "urlhaus_recent",
    description: "Get recent malware URLs from URLhaus",
    inputSchema: {
      type: "object" as const,
      properties: {
        limit: {
          type: "number",
          description: "Number of URLs to retrieve (default: 25)",
        },
      },
      required: [],
    },
  },
  {
    name: "malwarebazaar_hash",
    description: "Look up malware sample by hash on MalwareBazaar",
    inputSchema: {
      type: "object" as const,
      properties: {
        hash: {
          type: "string",
          description: "MD5, SHA1, or SHA256 hash",
        },
      },
      required: ["hash"],
    },
  },
  {
    name: "malwarebazaar_recent",
    description: "Get recent malware samples from MalwareBazaar",
    inputSchema: {
      type: "object" as const,
      properties: {
        limit: {
          type: "number",
          description: "Number of samples (default: 25, max: 1000)",
        },
      },
      required: [],
    },
  },
  {
    name: "malwarebazaar_tag",
    description: "Get malware samples by tag (e.g., 'emotet', 'cobalt-strike', 'ransomware')",
    inputSchema: {
      type: "object" as const,
      properties: {
        tag: {
          type: "string",
          description: "Malware tag to search for",
        },
        limit: {
          type: "number",
          description: "Number of samples (default: 25)",
        },
      },
      required: ["tag"],
    },
  },
  {
    name: "threatfox_iocs",
    description: "Get recent IOCs from ThreatFox (C2 servers, malware infrastructure)",
    inputSchema: {
      type: "object" as const,
      properties: {
        days: {
          type: "number",
          description: "Get IOCs from last N days (default: 7)",
        },
      },
      required: [],
    },
  },
  {
    name: "threatfox_search",
    description: "Search ThreatFox for IOCs by malware family or tag",
    inputSchema: {
      type: "object" as const,
      properties: {
        search_term: {
          type: "string",
          description: "Malware family or tag (e.g., 'Emotet', 'CobaltStrike')",
        },
      },
      required: ["search_term"],
    },
  },
  {
    name: "feodo_tracker",
    description: "Get active botnet C2 servers from Feodo Tracker",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  }
);

// Create server instance
const server = new Server(
  {
    name: "mcp-threatintel",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: TOOLS };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "threatintel_status": {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              configured_services: {
                otx: services.otx ? "configured" : "not configured (set OTX_API_KEY)",
                abuseipdb: services.abuseipdb ? "configured" : "not configured (set ABUSEIPDB_API_KEY)",
                greynoise: services.greynoise ? "configured" : "not configured (set GREYNOISE_API_KEY)",
                abusech: "available (no auth required for most queries)",
              },
              available_tools: TOOLS.map(t => t.name),
            }, null, 2),
          }],
        };
      }

      // Unified IP lookup
      case "threatintel_lookup_ip": {
        const { ip } = args as { ip: string };
        const results: Record<string, unknown> = { ip };

        // AbuseIPDB
        if (services.abuseipdb) {
          try {
            const abuseResult = await apiRequest<{ data: unknown }>(
              `${config.abuseipdb.baseUrl}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
              { headers: { Key: config.abuseipdb.apiKey! } }
            );
            results.abuseipdb = abuseResult.data;
          } catch (e) {
            results.abuseipdb = { error: e instanceof Error ? e.message : String(e) };
          }
        }

        // OTX
        if (services.otx) {
          try {
            const otxResult = await apiRequest<unknown>(
              `${config.otx.baseUrl}/indicators/IPv4/${ip}/general`,
              { headers: { "X-OTX-API-KEY": config.otx.apiKey! } }
            );
            results.otx = otxResult;
          } catch (e) {
            results.otx = { error: e instanceof Error ? e.message : String(e) };
          }
        }

        // GreyNoise
        if (services.greynoise) {
          try {
            const gnResult = await apiRequest<unknown>(
              `${config.greynoise.baseUrl}/community/${ip}`,
              { headers: { key: config.greynoise.apiKey! } }
            );
            results.greynoise = gnResult;
          } catch (e) {
            results.greynoise = { error: e instanceof Error ? e.message : String(e) };
          }
        }

        return {
          content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
        };
      }

      // Unified domain lookup
      case "threatintel_lookup_domain": {
        const { domain } = args as { domain: string };
        const results: Record<string, unknown> = { domain };

        // OTX
        if (services.otx) {
          try {
            const otxResult = await apiRequest<unknown>(
              `${config.otx.baseUrl}/indicators/domain/${domain}/general`,
              { headers: { "X-OTX-API-KEY": config.otx.apiKey! } }
            );
            results.otx = otxResult;
          } catch (e) {
            results.otx = { error: e instanceof Error ? e.message : String(e) };
          }
        }

        // URLhaus
        try {
          const urlhausResult = await apiRequest<unknown>(
            config.abusech.urlhaus + "/host/",
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: `host=${encodeURIComponent(domain)}`,
            }
          );
          results.urlhaus = urlhausResult;
        } catch (e) {
          results.urlhaus = { error: e instanceof Error ? e.message : String(e) };
        }

        return {
          content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
        };
      }

      // Unified hash lookup
      case "threatintel_lookup_hash": {
        const { hash } = args as { hash: string };
        const results: Record<string, unknown> = { hash };

        // OTX
        if (services.otx) {
          try {
            const hashType = hash.length === 32 ? "MD5" : hash.length === 40 ? "SHA1" : "SHA256";
            const otxResult = await apiRequest<unknown>(
              `${config.otx.baseUrl}/indicators/file/${hashType}/${hash}/general`,
              { headers: { "X-OTX-API-KEY": config.otx.apiKey! } }
            );
            results.otx = otxResult;
          } catch (e) {
            results.otx = { error: e instanceof Error ? e.message : String(e) };
          }
        }

        // MalwareBazaar
        try {
          const mbResult = await apiRequest<unknown>(
            config.abusech.malwarebazaar,
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: `query=get_info&hash=${encodeURIComponent(hash)}`,
            }
          );
          results.malwarebazaar = mbResult;
        } catch (e) {
          results.malwarebazaar = { error: e instanceof Error ? e.message : String(e) };
        }

        return {
          content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
        };
      }

      // Unified URL lookup
      case "threatintel_lookup_url": {
        const { url } = args as { url: string };
        const results: Record<string, unknown> = { url };

        // OTX
        if (services.otx) {
          try {
            const otxResult = await apiRequest<unknown>(
              `${config.otx.baseUrl}/indicators/url/${encodeURIComponent(url)}/general`,
              { headers: { "X-OTX-API-KEY": config.otx.apiKey! } }
            );
            results.otx = otxResult;
          } catch (e) {
            results.otx = { error: e instanceof Error ? e.message : String(e) };
          }
        }

        // URLhaus
        try {
          const urlhausResult = await apiRequest<unknown>(
            config.abusech.urlhaus + "/url/",
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: `url=${encodeURIComponent(url)}`,
            }
          );
          results.urlhaus = urlhausResult;
        } catch (e) {
          results.urlhaus = { error: e instanceof Error ? e.message : String(e) };
        }

        return {
          content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
        };
      }

      // AbuseIPDB check
      case "abuseipdb_check": {
        if (!services.abuseipdb) throw new Error("AbuseIPDB not configured");
        const { ip, maxAgeInDays = 90 } = args as { ip: string; maxAgeInDays?: number };

        const result = await apiRequest<{ data: unknown }>(
          `${config.abuseipdb.baseUrl}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=${maxAgeInDays}&verbose`,
          { headers: { Key: config.abuseipdb.apiKey! } }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
        };
      }

      // OTX get pulses
      case "otx_get_pulses": {
        if (!services.otx) throw new Error("OTX not configured");
        const { limit = 10 } = args as { limit?: number };

        const result = await apiRequest<unknown>(
          `${config.otx.baseUrl}/pulses/subscribed?limit=${limit}`,
          { headers: { "X-OTX-API-KEY": config.otx.apiKey! } }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // OTX search pulses
      case "otx_search_pulses": {
        if (!services.otx) throw new Error("OTX not configured");
        const { query } = args as { query: string };

        const result = await apiRequest<unknown>(
          `${config.otx.baseUrl}/search/pulses?q=${encodeURIComponent(query)}`,
          { headers: { "X-OTX-API-KEY": config.otx.apiKey! } }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // GreyNoise IP
      case "greynoise_ip": {
        if (!services.greynoise) throw new Error("GreyNoise not configured");
        const { ip } = args as { ip: string };

        const result = await apiRequest<unknown>(
          `${config.greynoise.baseUrl}/community/${ip}`,
          { headers: { key: config.greynoise.apiKey! } }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // URLhaus lookup
      case "urlhaus_lookup": {
        const { url } = args as { url: string };

        // Try as URL first, then as host
        let result;
        if (url.startsWith("http")) {
          result = await apiRequest<unknown>(
            config.abusech.urlhaus + "/url/",
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: `url=${encodeURIComponent(url)}`,
            }
          );
        } else {
          result = await apiRequest<unknown>(
            config.abusech.urlhaus + "/host/",
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: `host=${encodeURIComponent(url)}`,
            }
          );
        }

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // URLhaus recent
      case "urlhaus_recent": {
        const { limit = 25 } = args as { limit?: number };

        const result = await apiRequest<unknown>(
          config.abusech.urlhaus + "/urls/recent/limit/" + limit + "/",
          { method: "GET" }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // MalwareBazaar hash lookup
      case "malwarebazaar_hash": {
        const { hash } = args as { hash: string };

        const result = await apiRequest<unknown>(
          config.abusech.malwarebazaar,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `query=get_info&hash=${encodeURIComponent(hash)}`,
          }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // MalwareBazaar recent
      case "malwarebazaar_recent": {
        const { limit = 25 } = args as { limit?: number };

        const result = await apiRequest<unknown>(
          config.abusech.malwarebazaar,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `query=get_recent&selector=${limit}`,
          }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // MalwareBazaar by tag
      case "malwarebazaar_tag": {
        const { tag, limit = 25 } = args as { tag: string; limit?: number };

        const result = await apiRequest<unknown>(
          config.abusech.malwarebazaar,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `query=get_taginfo&tag=${encodeURIComponent(tag)}&limit=${limit}`,
          }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // ThreatFox IOCs
      case "threatfox_iocs": {
        const { days = 7 } = args as { days?: number };

        const result = await apiRequest<unknown>(
          config.abusech.threatfox,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: "get_iocs", days }),
          }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // ThreatFox search
      case "threatfox_search": {
        const { search_term } = args as { search_term: string };

        const result = await apiRequest<unknown>(
          config.abusech.threatfox,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: "search_ioc", search_term }),
          }
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      // Feodo Tracker
      case "feodo_tracker": {
        // Feodo provides JSON feed of active C2s
        const result = await apiRequest<unknown>(
          "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        );

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Threat Intel MCP server running - configured: ${configuredServices.join(", ") || "abuse.ch (no auth)"}`);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
