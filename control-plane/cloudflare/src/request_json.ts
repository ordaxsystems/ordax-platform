/** Read a bounded JSON object from a Request or Response stream without unbounded buffering. */
export async function readBoundedJsonObject(
  request: Request | Response,
  maxBytes: number,
): Promise<Record<string, unknown> | null> {
  if (!request.body) return null;
  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let bytes = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) return null;
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    const parsed: unknown = JSON.parse(text);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  } finally {
    // A Request.clone() body is a tee: awaiting cancellation of one branch
    // can deadlock until the original branch is consumed by the MCP handler.
    // Initiate best-effort cancellation without holding up the caller.
    try { void reader.cancel().catch(() => {}); } catch { /* Already closed. */ }
    reader.releaseLock();
  }
}
