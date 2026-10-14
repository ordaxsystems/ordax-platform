type JsonObject = Record<string, unknown>;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const VISUAL_ACTIONS = new Set(["artifact.preview", "computer.screenshot", "browser.screenshot"]);
const object = (value: unknown): JsonObject | null => value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;

function rasterData(data: unknown, mime: unknown): string | null {
  if (typeof data !== "string" || data.length % 4 !== 0 || data.length > Math.ceil(MAX_IMAGE_BYTES / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(data)) return null;
  let bytes: string;
  try { bytes = atob(data); if (btoa(bytes) !== data) return null; } catch { return null; }
  if (bytes.length === 0 || bytes.length > MAX_IMAGE_BYTES) return null;
  if (mime === "image/png" && bytes.startsWith("\x89PNG\r\n\x1a\n")) return data;
  if (mime === "image/jpeg" && bytes.startsWith("\xff\xd8\xff") && bytes.endsWith("\xff\xd9")) return data;
  if (mime === "image/webp" && bytes.startsWith("RIFF") && bytes.slice(8, 12) === "WEBP") return data;
  return null;
}

export function textToolResult(payload: unknown, isError = false): JsonObject {
  const structured = object(payload) ?? { value: payload };
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }], structuredContent: structured, isError };
}

// Pixels come only from the already-authorized Product result. Never fetch arbitrary URLs or local paths.
export function actionToolResult(payload: JsonObject): JsonObject {
  const action = object(payload.action), result = object(action?.result), data = object(result?.data);
  const pending = payload.pending === true;
  const failed = payload.ok === false || (!pending && Boolean(action && (action.status !== "succeeded" || result?.ok === false)));
  if (pending || failed || !action || !VISUAL_ACTIONS.has(String(action.name)) || !data || !("base64" in data)) return textToolResult(payload, failed);
  const pixels = rasterData(data.base64, data.mime_type);
  const { base64: _pixels, ...metadata } = data;
  const safe = { ...payload, action: { ...action, result: { ...result, data: { ...metadata, image_available: Boolean(pixels) } } } };
  if (!pixels) return textToolResult({ ...safe, image_delivery_error: "invalid_or_oversized_raster" }, true);
  const response = textToolResult(safe);
  (response.content as JsonObject[]).push({ type: "image", data: pixels, mimeType: data.mime_type });
  return response;
}

export function authenticationToolResult(request: Request, requestId?: string): JsonObject {
  const challenge = `Bearer resource_metadata="${new URL("/.well-known/oauth-protected-resource", request.url)}", error="invalid_token", error_description="Connect or reconnect your ORDAX account to continue"`;
  return { ...textToolResult({ ok: false, error: "authentication_required", ...(requestId ? { request_id: requestId, pending: true, message: "Reconnect, then check ordax_action_status with this request_id; do not repeat the original action." } : {}) }, true), _meta: { "mcp/www_authenticate": [challenge] } };
}
