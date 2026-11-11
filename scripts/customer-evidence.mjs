import assert from 'node:assert/strict';

export function assertCustomerFinding(payload, { findingId, firewallId, requestId, expectedText }) {
  const finding = payload?.finding;
  assert(finding && typeof finding === 'object', 'MCP returned no finding evidence');
  assert(finding.finding_id === findingId, 'MCP evidence identified a different finding');
  assert(finding.firewall_id === firewallId, 'MCP evidence identified a different firewall');
  assert(finding.metadata?.silmaril?.request_id === requestId, 'MCP evidence request correlation was not exact');
  assert(typeof finding.text === 'string' && finding.text.trim(), 'MCP finding payload was unavailable');
  assert(typeof expectedText === 'string' && expectedText.length > 0, 'Missing shared scenario expectation');
  assert(finding.text.includes(expectedText), 'MCP finding did not contain the controlled customer input');
}
