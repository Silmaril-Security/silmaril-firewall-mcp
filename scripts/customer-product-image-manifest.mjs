import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';

export function publicationConfig(repository, commit) {
  if (typeof repository !== 'string' || repository !== repository.trim() || !/^[0-9]{12}\.dkr\.ecr\.us-west-2\.amazonaws\.com\/[a-z0-9]+(?:[._/-][a-z0-9]+)*$/.test(repository ?? '')) {
    throw new Error('An exact us-west-2 ECR repository is required');
  }
  if (typeof commit !== 'string' || commit.length !== 40 || !/^[a-f0-9]{40}$/.test(commit)) throw new Error('A full source commit is required');
  return { repository, commit, tag: `mcp-${commit}`, repositoryName: repository.split('/').slice(1).join('/') };
}

export function imageReceipt(repository, commit, digest, inspection) {
  publicationConfig(repository, commit);
  if (typeof digest !== 'string' || digest.length !== 71 || !/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error('An exact image digest is required');
  const labels = inspection?.Config?.Labels;
  if (inspection?.Os !== 'linux' || inspection?.Architecture !== 'amd64'
    || labels?.['com.silmaril.firewall-mcp.commit'] !== commit
    || labels?.['com.silmaril.firewall-mcp.mode'] !== 'customer_hosted'
    || !inspection?.RepoDigests?.includes(`${repository}@${digest}`)) {
    throw new Error('Published image platform, revision, mode, or digest differs from the selected source');
  }
  return { uri: `${repository}@${digest}`, sha256: digest.slice(7), commit };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const config = publicationConfig(process.env.AWS_CUSTOMER_PRODUCT_MCP_REPOSITORY, process.env.GITHUB_SHA);
  if (process.argv[2] === 'config') {
    process.stdout.write(JSON.stringify(config) + '\n');
  } else if (process.argv.length === 5) {
    const inspection = JSON.parse(readFileSync(process.argv[3], 'utf8'));
    if (!Array.isArray(inspection) || inspection.length !== 1) throw new Error('One inspected image is required');
    writeFileSync(process.argv[4], JSON.stringify(imageReceipt(config.repository, config.commit, process.argv[2], inspection[0])) + '\n');
  } else {
    throw new Error('Expected config or <digest> <inspection.json> <receipt.json>');
  }
}
