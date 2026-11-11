import { mkdirSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
for (const name of ['CUSTOMER_MCP_URL', 'CUSTOMER_MCP_ACCESS_TOKEN', 'CUSTOMER_FIREWALL_ID', 'CUSTOMER_REQUEST_ID']) {
  assert(process.env[name], `Missing live customer prerequisite: ${name}`);
}
const client = new Client({ name: 'silmaril-customer-tests', version: '0.1.0' });
const transport = new StreamableHTTPClientTransport(new URL(process.env.CUSTOMER_MCP_URL), {
  requestInit: { headers: { Authorization: `Bearer ${process.env.CUSTOMER_MCP_ACCESS_TOKEN}` } },
});
try {
  await client.connect(transport);
  const tools = await client.listTools();
  assert(tools.tools.some(tool => tool.name === 'list_findings'));
  const deadline = Date.now() + 120_000;
  let found;
  while (Date.now() < deadline) {
    const result = await client.callTool({ name: 'list_findings', arguments: {
      firewall_id: process.env.CUSTOMER_FIREWALL_ID, q: process.env.CUSTOMER_REQUEST_ID, range: '1h', pageSize: 100,
    } });
    assert(!result.isError, 'MCP findings request failed');
    // The compact projection must retain correlation to this exact customer request.
    const payload = result.structuredContent ?? JSON.parse(result.content.find(block => block.type === 'text').text);
    found = payload.findings?.find(row => row.finding_id && JSON.stringify(row.metadata).includes(process.env.CUSTOMER_REQUEST_ID));
    if (found) break;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  assert(found, 'MCP did not return the SDK request evidence');
  const detail = await client.callTool({ name: 'get_finding', arguments: {
    firewall_id: process.env.CUSTOMER_FIREWALL_ID, finding_id: found.finding_id,
    ...(found.region ? { region: found.region } : {}), reason: 'Automated customer acceptance: verify SDK evidence',
  } });
  assert(!detail.isError, 'Customer could not inspect the finding');
  if (process.env.CUSTOMER_EVIDENCE_OUTPUT) {
    mkdirSync(process.env.CUSTOMER_EVIDENCE_OUTPUT, { recursive: true });
    writeFileSync(`${process.env.CUSTOMER_EVIDENCE_OUTPUT}/mcp.json`, JSON.stringify({ finding_id: found.finding_id, request_id: process.env.CUSTOMER_REQUEST_ID }));
  }
  console.log('PASS: delegated customer can find SDK evidence through MCP');
} finally { await client.close(); }
