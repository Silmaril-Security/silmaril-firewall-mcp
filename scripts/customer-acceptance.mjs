import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { assertCustomerFinding } from './customer-evidence.mjs';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
const accessToken = process.env.CUSTOMER_MCP_ACCESS_TOKEN || (process.env.CUSTOMER_MCP_TOKEN_FILE ? JSON.parse(readFileSync(process.env.CUSTOMER_MCP_TOKEN_FILE, 'utf8')).access_token : undefined);
assert(accessToken, 'Missing delegated MCP access token');
for (const name of ['CUSTOMER_MCP_URL', 'CUSTOMER_FIREWALL_ID', 'CUSTOMER_REQUEST_ID', 'CUSTOMER_SCENARIO_PATH']) {
  assert(process.env[name], `Missing live customer prerequisite: ${name}`);
}
const client = new Client({ name: 'silmaril-customer-tests', version: '0.1.0' });
const transport = new StreamableHTTPClientTransport(new URL(process.env.CUSTOMER_MCP_URL), {
  requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
});
try {
  await client.connect(transport);
  const tools = await client.listTools();
  assert(tools.tools.some(tool => tool.name === 'list_findings'));
  const deadline = Date.now() + 120_000;
  let found;
  while (Date.now() < deadline) {
    const result = await client.callTool({ name: 'list_findings', arguments: {
      firewall_id: process.env.CUSTOMER_FIREWALL_ID, metadata: [{ key: 'silmaril.request_id', value: process.env.CUSTOMER_REQUEST_ID }], range: '1h', pageSize: 100,
    } });
    assert(!result.isError, 'MCP findings request failed');
    // The compact projection must retain correlation to this exact customer request.
    const payload = result.structuredContent ?? JSON.parse(result.content.find(block => block.type === 'text').text);
    assert((payload.findings?.length ?? 0) <= 1, 'Request metadata matched ambiguous findings');
    found = payload.findings?.find(row => row.finding_id);
    if (found) break;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  assert(found, 'MCP did not return the SDK request evidence');
  const detail = await client.callTool({ name: 'get_finding', arguments: {
    firewall_id: process.env.CUSTOMER_FIREWALL_ID, finding_id: found.finding_id,
    ...(found.region ? { region: found.region } : {}), reason: 'Automated customer acceptance: verify SDK evidence',
  } });

  assert(!detail.isError, 'Customer could not inspect the finding');
  const evidence = detail.structuredContent ?? JSON.parse(detail.content.find(block => block.type === 'text').text);
  const scenario = JSON.parse(readFileSync(process.env.CUSTOMER_SCENARIO_PATH, 'utf8'));
  assertCustomerFinding(evidence, {
    findingId: found.finding_id, firewallId: process.env.CUSTOMER_FIREWALL_ID,
    requestId: process.env.CUSTOMER_REQUEST_ID,
    expectedText: scenario.cases.find(item => item.id === 'injected-tool-response')?.text,
  });
  if (process.env.CUSTOMER_EVIDENCE_OUTPUT) {
    mkdirSync(process.env.CUSTOMER_EVIDENCE_OUTPUT, { recursive: true });
    writeFileSync(`${process.env.CUSTOMER_EVIDENCE_OUTPUT}/mcp.json`, JSON.stringify({ finding_id: found.finding_id, request_id: process.env.CUSTOMER_REQUEST_ID }));
  }
  if (process.env.CUSTOMER_OTHER_FIREWALL_ID) {
    const other = await client.callTool({ name: 'list_findings', arguments: { firewall_id: process.env.CUSTOMER_OTHER_FIREWALL_ID, range: '1h' } });
    assert(other.isError, 'Customer principal accessed a different tenant');
    const error = other.structuredContent?.error;
    assert(error && [403, 404].includes(error.status), 'Tenant isolation must deny access explicitly');
  }
  console.log('PASS: delegated customer can find SDK evidence through MCP');
} finally { await client.close(); }
