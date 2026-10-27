#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const greenfield = '/home/utpal/work/thegreendfeild';
if (!process.env.CX_GREENFIELD_FIXTURE_CHILD) {
  const home = mkdtempSync(join(tmpdir(), 'cx-greenfield-'));
  try {
    const result = spawnSync(process.execPath, ['--import', `${greenfield}/node_modules/tsx/dist/loader.mjs`, import.meta.filename], {
      env: { ...process.env, HOME: home, PI_CODING_AGENT_DIR: join(home, '.pi/agent'), CX_GREENFIELD_FIXTURE_CHILD: '1' },
      stdio: 'inherit',
    });
    if (result.error) throw result.error;
    process.exitCode = result.status ?? 1;
  } finally { rmSync(home, { recursive: true, force: true }); }
} else {
  const home = process.env.HOME;
  const email = 'greenfield-fixture@example.invalid';
  const jwt = value => `header.${Buffer.from(JSON.stringify(value)).toString('base64url')}.signature`;
  const auth = { tokens: { access_token: jwt({ exp: 4000000000 }), refresh_token: 'synthetic-refresh', id_token: jwt({ email }), account_id: 'fixture-account' } };
  mkdirSync(join(home, '.codex-accounts/accounts'), { recursive: true, mode: 0o700 });
  mkdirSync(join(home, '.codex'), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, '.codex-accounts/accounts', `${email}.json`), JSON.stringify({ email, auth }), { mode: 0o600 });
  writeFileSync(join(home, '.codex/auth.json'), JSON.stringify(auth), { mode: 0o600 });
  const { readCxRegistry } = await import(`${greenfield}/server/overview/cx-registry.ts`);
  const { coldCodexWindow, AlreadyWarmWindow } = await import(`${greenfield}/server/overview/codex-warm-eligibility.ts`);
  const { warmCodex } = await import(`${greenfield}/server/overview/codex-warm.ts`);
  const { cxCompletion } = await import(`${greenfield}/services/honcho-runtime/cx-reasoning.mjs`);
  const registry = await readCxRegistry(home);
  const account = registry.accounts.find(item => item.account.email === email);
  assert.ok(account?.account.active);
  console.log('PASS actual registry account and active selection');
  let used = 0, mode = 'warm', calls = 0;
  globalThis.fetch = async (url, options = {}) => {
    const endpoint = String(url);
    if (endpoint === 'https://chatgpt.com/backend-api/wham/usage') return Response.json({ plan_type: 'plus', rate_limit: { primary_window: { used_percent: used, limit_window_seconds: 18000, reset_after_seconds: 18000, reset_at: Math.floor(Date.now() / 1000) + 18000 } } });
    if (endpoint === 'http://127.0.0.1:8317/health') return Response.json({ status: 'ok', accounts: 1, targetedWarming: mode !== 'unsupported' });
    assert.equal(endpoint, 'http://127.0.0.1:8317/v1/responses', 'fixture must never reach another endpoint');
    calls++;
    let request;
    try { request = JSON.parse(options.body); }
    catch (error) { throw new Error('Actual adapter produced invalid JSON', { cause: error }); }
    if (mode === 'warm' || mode === 'failure') {
      assert.equal(options.headers['x-cx-warm-account'], email);
      assert.deepEqual(request, { model: 'gpt-6-luna', input: 'Reply with OK only.', stream: false, reasoning: { effort: 'low' } });
      if (mode === 'failure') return Response.json({ error: { message: 'sensitive fixture detail' } }, { status: 500 });
      return Response.json({ status: 'completed', output: [{ content: [{ type: 'output_text', text: 'OK' }] }] });
    }
    assert.ok(request.input.some(item => item.type === 'function_call_output' && item.call_id === 'call_fixture'));
    assert.deepEqual(request.tool_choice, { type: 'function', name: 'lookup' });
    assert.equal(request.text.format.type, 'json_schema');
    assert.equal(request.text.format.strict, true);
    return Response.json({ id: 'fixture', status: 'completed', output: [{ type: 'function_call', call_id: 'call_next', name: 'lookup', arguments: '{}' }], usage: { input_tokens: 4, output_tokens: 2, total_tokens: 6, input_tokens_details: { cached_tokens: 3 } } });
  };
  const cold = await coldCodexWindow(account.account.id);
  assert.equal(cold.email, email);
  console.log('PASS actual cold-account eligibility and fresh quota mapping');
  used = 1;
  await assert.rejects(coldCodexWindow(account.account.id), AlreadyWarmWindow);
  console.log('PASS actual already-warm account refusal');
  await warmCodex(email);
  assert.equal(calls, 1);
  console.log('PASS actual fixed-payload account-targeted warming');
  mode = 'failure';
  await assert.rejects(warmCodex(email), error => !error.message.includes('sensitive fixture detail'));
  assert.equal(calls, 2);
  console.log('PASS actual warm failure sanitization and no retry');
  mode = 'unsupported';
  await assert.rejects(warmCodex(email), /No LLM call was sent/);
  assert.equal(calls, 2);
  console.log('PASS actual capability gate prevents unsupported warm spend');
  mode = 'honcho';
  const result = await cxCompletion({ messages: [{ role: 'user', content: 'lookup' }, { role: 'assistant', content: null, tool_calls: [{ id: 'call_fixture', function: { name: 'lookup', arguments: '{}' } }] }, { role: 'tool', tool_call_id: 'call_fixture', content: 'found' }], tools: [{ type: 'function', function: { name: 'lookup', parameters: { type: 'object', properties: {}, additionalProperties: false } } }], tool_choice: { type: 'function', function: { name: 'lookup' } }, response_format: { type: 'json_schema', json_schema: { name: 'fixture', strict: true, schema: { type: 'object', properties: {}, additionalProperties: false } } } });
  assert.equal(result.choices[0].finish_reason, 'tool_calls');
  assert.equal(result.choices[0].message.tool_calls[0].id, 'call_next');
  assert.deepEqual(result.usage, { prompt_tokens: 4, completion_tokens: 2, total_tokens: 6, prompt_tokens_details: { cached_tokens: 3 } });
  console.log('PASS actual Honcho tool history, schema, choice and usage mapping');
  console.log('7 actual-function fixture checks passed; no production calls or UI/service-control claims');
}
