import assert from 'node:assert/strict';
import test from 'node:test';
import { imageReceipt, publicationConfig } from './customer-product-image-manifest.mjs';

const repository = '123456789012.dkr.ecr.us-west-2.amazonaws.com/customer-apps';
const commit = 'a'.repeat(40);
const digest = `sha256:${'b'.repeat(64)}`;
function inspection() {
  return { Os: 'linux', Architecture: 'amd64', RepoDigests: [`${repository}@${digest}`], Config: { Labels: {
    'com.silmaril.firewall-mcp.commit': commit, 'com.silmaril.firewall-mcp.mode': 'customer_hosted',
  } } };
}

test('receipt binds the exact immutable image, platform and customer source', () => {
  assert.deepEqual(imageReceipt(repository, commit, digest, inspection()), { uri: `${repository}@${digest}`, sha256: 'b'.repeat(64), commit });
  assert.equal(publicationConfig(repository, commit).tag, `mcp-${commit}`);
});
for (const bad of ['latest', digest.toUpperCase(), 'sha256:' + 'b'.repeat(63)]) {
  test(`reject mutable or invalid digest ${bad}`, () => assert.throws(() => imageReceipt(repository, commit, bad, inspection())));
}
for (const change of [
  (x) => { x.Architecture = 'arm64'; },
  (x) => { x.Os = 'windows'; },
  (x) => { x.RepoDigests = []; },
  (x) => { x.Config.Labels['com.silmaril.firewall-mcp.commit'] = 'c'.repeat(40); },
  (x) => { x.Config.Labels['com.silmaril.firewall-mcp.mode'] = 'hosted'; },
]) {
  test(`reject an image with a mismatched identity: ${change}`, () => {
    const image = inspection(); change(image);
    assert.throws(() => imageReceipt(repository, commit, digest, image));
  });
}
for (const bad of [repository + ':latest', repository.replace('us-west-2', 'eu-west-1'), repository + '\n', 'https://' + repository]) {
  test(`reject invalid repository ${JSON.stringify(bad)}`, () => assert.throws(() => publicationConfig(bad, commit)));
}
