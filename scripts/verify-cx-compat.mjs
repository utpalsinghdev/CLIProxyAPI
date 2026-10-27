#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Non-generating checks only. Successful inference and account selection need separate evidence.
const args = process.argv.slice(2);
function option(name) {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}
let base;
try {
  base = new URL(option('--base') ?? 'http://127.0.0.1:8321');
} catch {
  console.error('Invalid --base URL');
  process.exit(2);
}
if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) {
  throw new Error('Use an HTTP(S) proxy URL without credentials');
}
const remoteWarm = args.includes('--remote-warm');
const suite = option('--suite') ?? 'all';
assert.ok(['all', 'warming'].includes(suite), 'Unknown suite');
const model = option('--model') ?? 'gpt-6-luna';
const keyFile = option('--key-file');
const authorization = keyFile ? `Bearer ${(await readFile(keyFile, 'utf8')).trim()}` : undefined;
const warm = { model: 'gpt-6-luna', input: 'Reply with OK only.', stream: false, reasoning: { effort: 'low' } };
const cases = [
  { name: 'health contract', path: '/health', status: 200, check(body) {
    assert.equal(body.status, 'ok');
    assert.ok(Number.isSafeInteger(body.accounts) && body.accounts >= 0);
    assert.equal(body.targetedWarming, true);
    assert.deepEqual(Object.keys(body).sort(), ['accounts', 'status', 'targetedWarming']);
  } },
  { name: 'browser origin rejected', path: '/health', headers: { Origin: 'https://example.invalid' }, status: 403 },
  { name: 'cross-site rejected', path: '/health', headers: { 'Sec-Fetch-Site': 'cross-site' }, status: 403 },
  { name: 'warm extra field rejected', path: '/v1/responses', method: 'POST', headers: { 'x-cx-warm-account': 'fixture@example.invalid' }, body: { ...warm, extra: true }, status: 400 },
  { name: 'warm wrong model rejected', path: '/v1/responses', method: 'POST', headers: { 'x-cx-warm-account': 'fixture@example.invalid' }, body: { ...warm, model: 'invalid-cx-parity-model' }, status: 400 },
  { name: 'warm wrong input rejected', path: '/v1/responses', method: 'POST', headers: { 'x-cx-warm-account': 'fixture@example.invalid' }, body: { ...warm, input: '' }, status: 400 },
  { name: 'warm stream rejected', path: '/v1/responses', method: 'POST', headers: { 'x-cx-warm-account': 'fixture@example.invalid' }, body: { ...warm, stream: true }, status: 400 },
  { name: 'warm reasoning extras rejected', path: '/v1/responses', method: 'POST', headers: { 'x-cx-warm-account': 'fixture@example.invalid' }, body: { ...warm, reasoning: { effort: 'low', extra: true } }, status: 400 },
  { name: 'warm invalid JSON rejected', path: '/v1/responses', method: 'POST', headers: { 'x-cx-warm-account': 'fixture@example.invalid' }, raw: '{', status: 400 },
  { name: 'warm compact rejected', path: '/v1/responses/compact', method: 'POST', headers: { 'x-cx-warm-account': 'fixture@example.invalid' }, body: { ...warm, input: '' }, status: 400 },
];
if (suite === 'all') cases.push(
  { name: 'unknown path rejected', path: '/cx-parity-no-such-route', status: 404 },
  { name: 'wrong health method rejected', path: '/health', method: 'POST', status: 405, allow: 'GET' },
  { name: 'wrong responses method rejected', path: '/v1/responses', method: 'GET', status: 405, allow: 'POST' },
  { name: 'malformed JSON rejected', path: '/v1/responses', method: 'POST', raw: '{', status: 400 },
  { name: 'nonobject JSON rejected', path: '/v1/responses', method: 'POST', body: [], status: 400 },
  { name: 'missing model rejected', path: '/v1/responses', method: 'POST', body: { input: '' }, status: 400 },
  { name: 'missing input rejected', path: '/v1/responses', method: 'POST', body: { model }, status: 400 },
  { name: 'previous response rejected', path: '/v1/responses', method: 'POST', body: { model, input: '', previous_response_id: 'resp_fixture' }, status: 400 },
  { name: 'compressed JSON rejected', path: '/v1/responses', method: 'POST', headers: { 'Content-Encoding': 'gzip' }, raw: '{', status: 415 },
  { name: 'oversized version rejected', path: `/v1/models?client_version=${'x'.repeat(101)}`, status: 400 },
);
let failed = 0;
for (const test of cases) {
  try {
    const response = await fetch(new URL(test.path, base), {
      method: test.method ?? 'GET',
      headers: { ...(authorization ? { authorization } : {}), 'Content-Type': 'application/json', ...test.headers },
      body: test.raw ?? (test.body === undefined ? undefined : JSON.stringify(test.body)),
      redirect: 'error',
    });
    const raw = await response.text();
    const expectedStatus = remoteWarm && test.headers?.['x-cx-warm-account'] && test.raw === undefined ? 403 : test.status;
    assert.equal(response.status, expectedStatus, `HTTP ${response.status}, expected ${expectedStatus}`);
    const body = JSON.parse(raw);
    if (test.allow) assert.equal(response.headers.get('allow'), test.allow);
    if (test.status >= 400) {
      assert.equal(typeof body.error?.message, 'string');
      assert.equal(typeof body.error?.type, 'string');
      assert.ok(Object.hasOwn(body.error, 'code'));
    }
    test.check?.(body);
    console.log(`PASS ${test.name}`);
  } catch (error) {
    failed++;
    // Never print provider response bodies, keys, or account identities.
    console.log(`FAIL ${test.name}: ${error instanceof assert.AssertionError ? error.message.split('\n')[0] : 'request or JSON parsing failed'}`);
  }
}
console.log(`${cases.length - failed}/${cases.length} non-generating compatibility checks passed`);
process.exitCode = failed ? 1 : 0;
