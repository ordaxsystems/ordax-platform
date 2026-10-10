// Non-production Relay laboratory. This is NOT Product identity, a cloud inference
// provider, or the ChatGPT MCP connector. It binds to loopback intentionally.
import { createServer } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';

const MAX_BODY_BYTES = 8192;
const ID = /^[a-z][a-z0-9-]{1,62}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function digest(value) { return createHash('sha256').update(value, 'utf8').digest(); }
function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(body));
}

async function jsonBody(req) {
  if (req.headers['content-type'] !== 'application/json') throw new Error('invalid_body');
  const chunks = []; let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) throw new Error('invalid_body');
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_body');
    if (Object.keys(value).sort().join(',') !== 'prompt,request_id') throw new Error('invalid_body');
    if (typeof value.request_id !== 'string' || !UUID.test(value.request_id)) throw new Error('invalid_body');
    if (typeof value.prompt !== 'string' || !value.prompt.trim() || value.prompt.length > 2048) throw new Error('invalid_body');
    return value;
  } catch { throw new Error('invalid_body'); }
}

/**
 * One-way request ingress for three or more simulated clients. Credentials are
 * ephemeral, test-owned, and never the Product owner token. The only allowed
 * operation is client -> central inference adapter -> same client response.
 * There is intentionally no peer discovery or device-targeting operation.
 */
export async function startRelayLab({ devices, inference }) {
  if (!Array.isArray(devices) || devices.length < 2 || devices.length > 32 || typeof inference !== 'function') {
    throw new TypeError('invalid_lab_configuration');
  }
  const secrets = new Map();
  for (const item of devices) {
    if (!item || !ID.test(item.id) || typeof item.secret !== 'string' || item.secret.length < 32 || secrets.has(item.id)) {
      throw new TypeError('invalid_lab_device');
    }
    secrets.set(item.id, digest(item.secret));
  }
  const completed = new Map();
  const inflight = new Map();
  const server = createServer(async (req, res) => {
    // No clients or device details are leaked through discovery or error paths.
    if (req.url !== '/v1/infer' || req.method !== 'POST') return send(res, 404, { ok: false, error: 'not_found' });
    const deviceId = req.headers['x-ordax-lab-device-id'];
    const authorization = req.headers.authorization;
    const expected = typeof deviceId === 'string' ? secrets.get(deviceId) : undefined;
    const token = typeof authorization === 'string' && authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!expected || token.length < 32 || !timingSafeEqual(digest(token), expected)) {
      return send(res, 401, { ok: false, error: 'unauthorized' });
    }
    let payload;
    try { payload = await jsonBody(req); } catch { return send(res, 400, { ok: false, error: 'invalid_body' }); }
    const id = `${deviceId}:${payload.request_id}`;
    const inputDigest = digest(payload.prompt).toString('hex');
    const existing = completed.get(id);
    if (existing) {
      if (existing.inputDigest !== inputDigest) return send(res, 409, { ok: false, error: 'request_conflict' });
      return send(res, 200, { ok: true, request_id: payload.request_id, result: existing.result, replayed: true, source: 'lab-adapter' });
    }
    if (inflight.has(id)) return send(res, 409, { ok: false, error: 'request_pending' });
    if (Array.from(inflight.keys()).some(key => key.startsWith(`${deviceId}:`))) {
      return send(res, 429, { ok: false, error: 'device_busy' });
    }
    inflight.set(id, inputDigest);
    try {
      // Only the central adapter handles the content. It has no peer target.
      const answer = await inference({ deviceId, prompt: payload.prompt, requestId: payload.request_id });
      if (typeof answer !== 'string' || answer.length > 4096) throw new Error('invalid_adapter_response');
      // Bounded replay cache: laboratory only; no persistent history or shared user memory.
      if (completed.size >= 128) completed.delete(completed.keys().next().value);
      completed.set(id, { result: answer, inputDigest });
      return send(res, 200, { ok: true, request_id: payload.request_id, result: answer, replayed: false, source: 'lab-adapter' });
    } catch {
      return send(res, 503, { ok: false, error: 'adapter_unavailable' });
    } finally { inflight.delete(id); }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return Object.freeze({
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve())),
  });
}
