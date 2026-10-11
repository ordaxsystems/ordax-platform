// Relay laboratory compatibility entry. Canonical authorization, signed OAuth
// and PostgreSQL-backed read MCP projection are owned by the Platform source.
// Do not fork the implementation or create a second grant resolver.
export { createCanonicalCentralMcpReadHandlers,
  createCanonicalRelayReadOnlyHandlers } from "../../cloudflare/src/product_central_mcp.ts";
