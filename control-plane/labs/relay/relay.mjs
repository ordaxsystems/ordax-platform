// Loopback-only Relay laboratory. No Product authorization, real inference,
// ChatGPT session redistribution, LAN exposure or production device inventory.
import { createServer } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';

const MAX_BODY_BYTES = 8192;
const ID = /^[a-z][a-z0-9-]{1,62}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_DEVICES = 32;
const DEFAULT_TIMEOUT_MS = 20000;
const DEFAULT_RECEIPTS = 128;

function digest(value) { return createHash('sha256').update(value, 'utf8').digest(); }
function send(res, status, body) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}
async function jsonBody(req, operation) {
  if (req.headers['content-type'] !== 'application/json') throw Error('invalid_body');
  const chunks = []; let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) throw Error('invalid_body');
    chunks.push(chunk);
  }
  try {
    const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)
      || typeof payload.request_id !== 'string' || !UUID.test(payload.request_id)) throw Error('invalid_body');
    const keys = Object.keys(payload).sort().join(',');
    if (operation === 'cancel' && keys === 'request_id') return payload;
    if (operation === 'infer' && keys === 'prompt,request_id'
      && typeof payload.prompt === 'string' && payload.prompt.trim()
      && payload.prompt.length <= 2048) return payload;
  } catch { /* fail closed */ }
  throw Error('invalid_body');
}
function verifyClient(req, secrets) {
  const deviceId = req.headers['x-ordax-lab-device-id'];
  const auth = req.headers.authorization;
  const expected = typeof deviceId === 'string' ? secrets.get(deviceId) : undefined;
  const token = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!expected || token.length < 32 || !timingSafeEqual(digest(token), expected)) return null;
  return deviceId;
}

/**
 * Experimental, one-way spoke -> hub laboratory. No peer discovery/targeting.
 * Adapter result MUST be {deviceId, requestId, result}; timeout, cancellation
 * and failure receipts are terminal for their request ID (no auto retry).
 * Memory-only idempotency is deliberately capacity-limited and fails closed,
 * rather than evicting old receipts and silently replaying risky actions.
 */
export async function startRelayLab({
  devices, inference, inferenceTimeoutMs = DEFAULT_TIMEOUT_MS,
  maxReceipts = DEFAULT_RECEIPTS, adminToken = null,
}) {
  if (!Array.isArray(devices) || devices.length < 2 || devices.length > MAX_DEVICES
    || typeof inference !== 'function'
    || !Number.isInteger(inferenceTimeoutMs) || inferenceTimeoutMs < 25 || inferenceTimeoutMs > 60000
    || !Number.isInteger(maxReceipts) || maxReceipts < 1 || maxReceipts > 128
    || (adminToken !== null && (typeof adminToken !== 'string' || adminToken.length < 32))) {
    throw new TypeError('invalid_lab_configuration');
  }
  const secrets = new Map();
  const seenTokens = new Set();
  for (const item of devices) {
    if (!item || !ID.test(item.id) || typeof item.secret !== 'string'
      || item.secret.length < 32 || secrets.has(item.id)) throw new TypeError('invalid_lab_device');
    const hash = digest(item.secret);
    const hex = hash.toString('hex');
    if (seenTokens.has(hex)) throw new TypeError('duplicate_lab_credential');
    seenTokens.add(hex);
    secrets.set(item.id, hash);
  }
  if (adminToken !== null && seenTokens.has(digest(adminToken).toString('hex'))) {
    throw new TypeError('admin_credential_must_be_separate');
  }
  const adminHash = adminToken === null ? null : digest(adminToken);
  const completed = new Map();
  const inflight = new Map();
  const server = createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/v1/admin/status') {
      if (!adminHash) return send(res, 404, { ok: false, error: 'not_found' });
      const authorization = req.headers.authorization;
      const token = typeof authorization === 'string' && authorization.startsWith('Bearer ')
        ? authorization.slice(7) : '';
      if (token.length < 32 || !timingSafeEqual(digest(token), adminHash)) {
        return send(res, 401, { ok: false, error: 'unauthorized' });
      }
      const all = [...completed.values()];
      return send(res, 200, {
        schema: 'ordax.relay-lab-status/1',
        environment: 'loopback-laboratory',
        acceptingClients: secrets.size,
        activeRequests: inflight.size,
        retainedReceipts: completed.size,
        failedReceipts: all.filter(x => x.error).length,
        cancelledReceipts: all.filter(x => x.error === 'request_cancelled').length,
        timedOutReceipts: all.filter(x => x.error === 'adapter_timeout').length,
      });
    }
    const operation = req.method === 'POST' && req.url === '/v1/infer' ? 'infer'
      : req.method === 'POST' && req.url === '/v1/cancel' ? 'cancel' : null;
    if (!operation) return send(res, 404, { ok: false, error: 'not_found' });
    const deviceId = verifyClient(req, secrets);
    if (!deviceId) return send(res, 401, { ok: false, error: 'unauthorized' });
    let payload;
    try { payload = await jsonBody(req, operation); }
    catch { return send(res, 400, { ok: false, error: 'invalid_body' }); }

    const id = `${deviceId}:${payload.request_id}`;
    if (operation === 'cancel') {
      // No indication is given about presence/absence of other clients' IDs.
      inflight.get(id)?.controller.abort('cancelled');
      return send(res, 202, { ok: true, request_id: payload.request_id, accepted: true });
    }

    const inputDigest = digest(payload.prompt).toString('hex');
    const existing = completed.get(id);
    if (existing) {
      if (existing.inputDigest !== inputDigest) {
        return send(res, 409, { ok: false, error: 'request_conflict' });
      }
      if (existing.error) {
        return send(res, existing.status, {
          ok: false, error: existing.error, request_id: payload.request_id, replayed: true,
        });
      }
      return send(res, 200, {
        ok: true, request_id: payload.request_id, result: existing.result,
        replayed: true, source: 'lab-adapter',
      });
    }
    if (inflight.has(id)) return send(res, 409, { ok: false, error: 'request_pending' });
    // One active request per client. Include reserved pending receipts in the
    // capacity check so concurrent completions can never evict old receipts.
    if ([...inflight.keys()].some(key => key.startsWith(`${deviceId}:`))) {
      return send(res, 429, { ok: false, error: 'device_busy' });
    }
    if (completed.size + inflight.size >= maxReceipts) {
      return send(res, 503, { ok: false, error: 'lab_receipt_capacity_exhausted' });
    }

    const controller = new AbortController();
    inflight.set(id, { inputDigest, controller });
    const timer = setTimeout(() => controller.abort('timeout'), inferenceTimeoutMs);
    res.once('close', () => { if (!res.writableEnded) controller.abort('client_disconnected'); });
    const interruption = new Promise((_, reject) => {
      controller.signal.addEventListener('abort', () => reject(Error(String(controller.signal.reason))), { once: true });
    });
    try {
      const response = await Promise.race([
        Promise.resolve().then(() => inference({
          deviceId, requestId: payload.request_id, prompt: payload.prompt, signal: controller.signal,
        })),
        interruption,
      ]);
      if (controller.signal.aborted) throw Error(String(controller.signal.reason));
      if (!secrets.has(deviceId)) return send(res, 401, { ok: false, error: 'unauthorized' });
      if (!response || typeof response !== 'object' || Array.isArray(response)
        || Object.keys(response).sort().join(',') !== 'deviceId,requestId,result'
        || response.deviceId !== deviceId || response.requestId !== payload.request_id
        || typeof response.result !== 'string' || response.result.length > 4096) {
        throw Error('invalid_adapter_response');
      }
      completed.set(id, { inputDigest, result: response.result });
      send(res, 200, {
        ok: true, request_id: payload.request_id,
        result: response.result, replayed: false, source: 'lab-adapter',
      });
    } catch {
      if (!secrets.has(deviceId)) return send(res, 401, { ok: false, error: 'unauthorized' });
      const reason = controller.signal.reason;
      const error = reason === 'timeout' ? 'adapter_timeout'
        : reason === 'cancelled' ? 'request_cancelled'
        : reason === 'client_disconnected' ? 'request_abandoned'
        : reason === 'shutdown' ? 'relay_unavailable' : 'adapter_unavailable';
      const status = reason === 'timeout' ? 504 : reason === 'cancelled' ? 409 : 503;
      completed.set(id, { inputDigest, error, status });
      send(res, status, { ok: false, error, request_id: payload.request_id, replayed: false });
    } finally {
      clearTimeout(timer);
      inflight.delete(id);
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return Object.freeze({
    url: `http://127.0.0.1:${address.port}`,
    revokeDevice: deviceId => {
      if (typeof deviceId !== 'string' || !secrets.delete(deviceId)) return false;
      inflight.forEach((entry, key) => {
        if (key.startsWith(`${deviceId}:`)) entry.controller.abort('revoked');
      });
      for (const key of completed.keys()) {
        if (key.startsWith(`${deviceId}:`)) completed.delete(key);
      }
      return true;
    },
    close: () => {
      for (const entry of inflight.values()) entry.controller.abort('shutdown');
      return new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
    },
  });
}
