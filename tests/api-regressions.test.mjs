import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rmdir, symlink, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

let client;
let server;
let requests = [];
let malwareBazaarData = [];

before(async () => {
  process.env.OTX_API_KEY = "otx-test-key";
  process.env.ABUSECH_AUTH_KEY = "abusech-test-key";

  ({ server } = await import("../dist/index.js"));

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: "regression-tests", version: "1.0.0" });
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
});

beforeEach(() => {
  requests = [];
  malwareBazaarData = [];

  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    requests.push({ url, init });

    const body = url.includes("mb-api.abuse.ch")
      ? { query_status: "ok", data: malwareBazaarData }
      : { query_status: "ok" };

    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
});

after(async () => {
  delete globalThis.fetch;
  await client.close();
  await server.close();
});

async function callTool(name, args) {
  const result = await client.callTool({ name, arguments: args });
  assert.notEqual(result.isError, true, result.content?.[0]?.text);
  return JSON.parse(result.content[0].text);
}

test("OTX file hash lookup omits the hash type path segment", async () => {
  const hash = "a".repeat(64);

  await callTool("threatintel_lookup_hash", { hash });

  assert.ok(requests.some(({ url }) =>
    url === `https://otx.alienvault.com/api/v1/indicators/file/${hash}/general`
  ));
  assert.ok(requests.every(({ url }) => !url.includes("/file/SHA256/")));
});

test("combined abuse.ch lookups send the configured Auth-Key", async () => {
  await callTool("threatintel_lookup_domain", { domain: "example.com" });
  await callTool("threatintel_lookup_hash", { hash: "b".repeat(64) });
  await callTool("threatintel_lookup_url", { url: "https://example.com/payload" });

  const abuseChRequests = requests.filter(({ url }) =>
    url.includes("urlhaus-api.abuse.ch") || url.includes("mb-api.abuse.ch")
  );
  assert.equal(abuseChRequests.length, 3);
  for (const { init } of abuseChRequests) {
    assert.equal(init.headers["Auth-Key"], "abusech-test-key");
  }
});

test("malwarebazaar_recent requests selector 100 and slices locally", async () => {
  malwareBazaarData = Array.from({ length: 5 }, (_, id) => ({ id }));

  const result = await callTool("malwarebazaar_recent", { limit: 2 });

  const request = requests.find(({ url }) => url.includes("mb-api.abuse.ch"));
  assert.equal(request.init.body, "query=get_recent&selector=100");
  assert.deepEqual(result.data, [{ id: 0 }, { id: 1 }]);
});

test("threatfox_search describes IOC value matching", async () => {
  const { tools } = await client.listTools();
  const tool = tools.find(({ name }) => name === "threatfox_search");

  assert.equal(tool.description, "Search ThreatFox for an IOC value (domain, IP:port, or URL)");
  assert.match(tool.inputSchema.properties.search_term.description, /IOC value/);
});

test("server starts and completes an MCP handshake through an executable symlink", async () => {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), "mcp-threatintel-"));
  const executablePath = join(temporaryDirectory, "mcp-threatintel");
  const serverPath = new URL("../dist/index.js", import.meta.url);
  await symlink(serverPath, executablePath);

  const symlinkClient = new Client({ name: "symlink-regression-test", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [executablePath],
    stderr: "pipe",
  });

  try {
    await symlinkClient.connect(transport);
    const { tools } = await symlinkClient.listTools();
    assert.ok(tools.some(({ name }) => name === "threatintel_status"));
  } finally {
    await symlinkClient.close();
    await unlink(executablePath);
    await rmdir(temporaryDirectory);
  }
});
