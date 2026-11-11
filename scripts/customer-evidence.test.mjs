import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertCustomerFinding } from './customer-evidence.mjs';
const expected = { findingId: 'finding', firewallId: 'firewall', requestId: 'run-request', expectedText: 'controlled attack' };
const valid = () => ({ finding: { finding_id: 'finding', firewall_id: 'firewall', metadata: { silmaril: { request_id: 'run-request' } }, text: 'controlled attack' } });
test('exact correlated customer evidence passes', () => assertCustomerFinding(valid(), expected));
test('successful but missing evidence cannot pass', () => {
  for (const payload of [{}, { finding: null }, { finding: {} }]) assert.throws(() => assertCustomerFinding(payload, expected));
});
test('contains matches and unrelated findings cannot pass', () => {
  for (const change of [
    { finding_id: 'other' }, { firewall_id: 'other' }, { metadata: { silmaril: { request_id: 'run-request-extra' } } },
    { text: '' }, { text: 'unrelated payload' },
  ]) assert.throws(() => assertCustomerFinding({ finding: { ...valid().finding, ...change } }, expected));
});
