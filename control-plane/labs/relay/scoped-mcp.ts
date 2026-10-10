// Relay-facing, fail-closed MCP projection. Experimental until an authenticated
// Product resolver supplies immutable per-request scopes. No extra identity/store.
import type { OrdaxMcpHandlers } from "../../cloudflare/src/mcp_http.ts";

type Action = "workspace.directory_list" | "workspace.file_stat" | "workspace.text_read";
const ALLOWED = new Set<Action>(["workspace.directory_list", "workspace.file_stat", "workspace.text_read"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PROJECT = /^[a-zA-Z0-9_-]{1,100}$/;
type Scope = Readonly<{
  deviceId: string;
  subjectId: string;
  clientId: string;
  spaceId: string | null;
  project: string;
  rootPath: string;
  actions: readonly Action[];
}>;
type Resolver = (request: Request) => Promise<Scope | null>;
const json = (body: unknown, status = 200) => Response.json(body, {status, headers: {"cache-control":"no-store"}});
const denied = () => json({ok:false,error:"relay_scope_denied"},403);
const unavailable = () => json({ok:false,error:"relay_scope_unavailable"},503);
const validSegment = (s: string) => s !== "" && s !== "." && s !== ".." && !/[\\:\x00-\x1f]/.test(s);
function pathWithin(root: string, value: unknown): boolean {
  if (typeof value !== "string" || value.length > 512 || value.startsWith("/") || value.endsWith("/")) return false;
  const segments = value.split("/");
  const base = root.split("/");
  return segments.every(validSegment) && base.every(validSegment)
    && segments.length >= base.length && base.every((part, n) => segments[n] === part);
}
function validScope(scope: Scope | null): scope is Scope {
  return !!scope && UUID.test(scope.deviceId) && UUID.test(scope.subjectId)
    && typeof scope.clientId === "string" && /^[a-zA-Z0-9_-]{3,100}$/.test(scope.clientId)
    && (scope.spaceId === null || UUID.test(scope.spaceId)) && PROJECT.test(scope.project)
    && pathWithin(scope.rootPath, scope.rootPath)
    && Array.isArray(scope.actions) && scope.actions.length > 0
    && scope.actions.every(item => ALLOWED.has(item));
}
function permittedArgs(action: Action, args: unknown, root: string): boolean {
  if (!args || typeof args !== "object" || Array.isArray(args)) return false;
  const input = args as Record<string,unknown>;
  const keys = action === "workspace.directory_list"
    ? ["path","max_depth","max_entries","include_hidden"]
    : action === "workspace.text_read" ? ["path","start_line","end_line"] : ["path"];
  if (Object.keys(input).some(key => !keys.includes(key)) || !pathWithin(root,input.path)) return false;
  for (const [key,value] of Object.entries(input)) {
    if (key === "path") continue;
    if (key === "include_hidden" && typeof value === "boolean") continue;
    if (key === "max_depth" && Number.isInteger(value) && (value as number) >= 1 && (value as number) <= 12) continue;
    if (key === "max_entries" && Number.isInteger(value) && (value as number) >= 1 && (value as number) <= 5000) continue;
    if ((key === "start_line" || key === "end_line") && Number.isInteger(value) && (value as number) >= 1) continue;
    return false;
  }
  return true;
}
async function body(response: Response | Request): Promise<Record<string,unknown>|null> {
  try {
    const value = await response.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string,unknown> : null;
  } catch { return null; }
}

/**
 * The resolver MUST authenticate a distinct Relay client at the trusted server
 * boundary. No request JSON, LLM content or arbitrary device header may mint
 * this scope. Wraps the actual Product MCP handlers, not a second MCP server.
 */
export function scopeRelayMcp(handlers: OrdaxMcpHandlers, resolver: Resolver): OrdaxMcpHandlers {
  const scopeFor = async (request: Request) => {
    try { const value = await resolver(request); return validScope(value) ? value : null; }
    catch { return null; }
  };
  return {
    async session(request) {
      const scope = await scopeFor(request);
      if (!scope) return denied();
      const upstream = await handlers.session(request);
      if (!upstream.ok || (await body(upstream))?.ok !== true) return denied();
      // Never expose the privileged hub subject or inventory to the spoke.
      return json({ok:true,session:{subject_id:scope.subjectId,client_id:scope.clientId}});
    },
    async targets(request) {
      const scope = await scopeFor(request);
      if (!scope) return denied();
      const upstream = await handlers.targets(request);
      if (!upstream.ok) return unavailable();
      const result = await body(upstream);
      if (result?.ok !== true || !Array.isArray(result.targets)) return unavailable();
      const found = result.targets.find(t => t && typeof t === "object"
        && !Array.isArray(t) && (t as Record<string,unknown>).device_id === scope.deviceId);
      if (!found) return json({ok:true,targets:[]});
      const item = found as Record<string,unknown>;
      return json({ok:true,targets:[{device_id:scope.deviceId,
        device_name:typeof item.device_name === "string" ? item.device_name.slice(0,128) : scope.deviceId,
        online:typeof item.online === "boolean" ? item.online : null,
        grants:[],grant_groups:[]}]});
    },
    async createAction(request) {
      const scope = await scopeFor(request);
      if (!scope) return denied();
      const data = await body(request.clone());
      if (!data || data.device_id !== scope.deviceId || data.space_id !== scope.spaceId
        || data.project !== scope.project || typeof data.action !== "string"
        || !scope.actions.includes(data.action as Action)
        || !permittedArgs(data.action as Action,data.arguments,scope.rootPath)
        || Object.keys(data).some(k => !["device_id","space_id","project","action","arguments"].includes(k))) return denied();
      return handlers.createAction(request);
    },
    async getAction(request, requestId) {
      const scope = await scopeFor(request);
      if (!scope) return denied();
      const upstream = await handlers.getAction(request, requestId);
      if (!upstream.ok) return denied();
      const payload = await body(upstream);
      const action = payload?.action;
      if (payload?.ok !== true || !action || typeof action !== "object" || Array.isArray(action)) return denied();
      const data = action as Record<string,unknown>;
      // Both subject and exact client must be verified by canonical authority.
      // A central operator credential or a shared device is never sufficient.
      if (data.request_id !== requestId || data.device_id !== scope.deviceId
        || data.subject_id !== scope.subjectId || data.client_id !== scope.clientId
        || !scope.actions.includes(data.action as Action)
        || data.project !== scope.project) return denied();
      return json(payload);
    }
  };
}
