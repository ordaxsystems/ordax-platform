// Compatibility re-export for Relay laboratory callers.
// Canonical scope enforcement lives with Product MCP in Cloudflare source.
// Keep one implementation only; tests and legacy lab imports remain valid.
export { scopeRelayMcp } from "../../cloudflare/src/product_mcp_scoped.ts";
