import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const value = process.env.CLOUDFEN_BACKEND_ORIGIN?.trim();
if (!value) {
  throw new Error('Set CLOUDFEN_BACKEND_ORIGIN in Netlify to the HTTPS origin of the PHP backend.');
}

let backend;
try {
  backend = new URL(value);
} catch {
  throw new Error('CLOUDFEN_BACKEND_ORIGIN must be a valid HTTPS origin.');
}

if (
  backend.protocol !== 'https:' ||
  backend.pathname !== '/' ||
  backend.search ||
  backend.hash ||
  backend.username ||
  backend.password
) {
  throw new Error('CLOUDFEN_BACKEND_ORIGIN must contain only an HTTPS origin, without credentials, path, query, or fragment.');
}

const publishDirectory = path.resolve('netlify-dist');
await mkdir(publishDirectory, { recursive: true });
await writeFile(
  path.join(publishDirectory, 'index.html'),
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CloudFen</title></head><body>CloudFen HR Workspace</body></html>\n',
  'utf8',
);
await writeFile(
  path.join(publishDirectory, '_redirects'),
  `/ ${backend.origin}/ 200!\n/* ${backend.origin}/:splat 200!\n`,
  'utf8',
);

console.log(`Netlify proxy rules generated for ${backend.origin}`);
