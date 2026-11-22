/**
 * Product MCP over the canonical PostgreSQL authority.
 *
 * This is the direct-user ChatGPT MCP path. It may coordinate OAuth, device
 * identity, grants and short-lived session attestation, but it MUST NOT relay
 * the user's prompt to a model provider. Historical `product_central_*` names
 * in this entrypoint refer to session/attestation machinery, not to the OrdaX
 * Central multi-client inference relay.
 *
 * Never imports the legacy D1 Worker and never makes model arguments an
 * authorization source. Device actions are dispatched only through the
 * Runtime-attested Product session and current canonical PostgreSQL grants.
 */
export { ProductDeviceWake } from "./product_device_wake.ts";
import { waitProductActionCompletion } from "./product_device_wake.ts";
import { handleOrdaxMcp, MAX_MCP_REQUEST_BYTES, validMcpToolCallEnvelope, type OrdaxMcpHandlers } from "./mcp_http.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { handleProductDevicePresence, PRODUCT_DEVICE_PRESENCE_PATH } from "./product_device_presence.ts";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts";
import { handleProductOwnerMcpUsageRead, PRODUCT_OWNER_MCP_USAGE_PATH } from "./product_mcp_usage_read.ts";
import { productAuthConfigured, productOwnerAccountSession,
  requestScopedProductMcpAuthenticator, type ProductAuthEnv } from "./product_auth.ts";
import {
  checkCanonicalProductPostgresReadiness,
  productPostgresConfigured,
  listRecentProductMcpActions,
  pruneProductMcpUsage,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { checkCanonicalProductOAuthDiscovery } from "./product_oauth_readiness.ts";
import {
  handleProductDeviceCentralSession,
  openCentralSessionFromMcp,
  resolveCentralSessionFromMcp,
  PRODUCT_DEVICE_CENTRAL_SESSION_PATH,
} from "./product_central_device_session.ts";
import {
  createAttestedDeviceActionHandler,
  type AttestedMcpDevice,
} from "./product_mcp_attested_device_action.ts";
import { createAttestedProjectActionHandler } from "./product_mcp_attested_project_action.ts";
import { createAttestedProjectContinuityHandler } from "./product_mcp_attested_project_continuity.ts";
import { createAttestedRepositoryCatalogHandler } from "./product_mcp_attested_repository_catalog.ts";
import {
  handleProductDeviceSetup,
  PRODUCT_DEVICE_SETUP_PATH,
} from "./product_device_setup.ts";
import {
  handleProductDeviceTransport,
  PRODUCT_DEVICE_TRANSPORT_PREFIX,
} from "./product_device_transport.ts";
import {
  handleProductOwnerGrantAdmin,
  PRODUCT_OWNER_REMOTE_AUTHORITY_PATH,
  PRODUCT_OWNER_MCP_DEVICES_PATH,
  PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH,
  PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH,
  PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH,
  PRODUCT_OWNER_CENTRAL_DEV_TARGET_PATH,
} from "./product_owner_grant_admin.ts";
import {
  handleProductOwnerProjectScope,
  PRODUCT_OWNER_PROJECT_SCOPE_PATH,
} from "./product_owner_project_scope.ts";
import {
  handleProductOwnerProjectOnboarding,
  PRODUCT_OWNER_PROJECT_ONBOARDING_PATH,
  PRODUCT_OWNER_PROJECT_ONBOARDING_PROJECTS_PATH,
  PRODUCT_OWNER_PROJECT_DEVICE_BINDING_INTENTS_PATH,
} from "./product_owner_project_onboarding.ts";
import {
  handleProductOwnerGithubAuthorization,
  PRODUCT_OWNER_GITHUB_AUTHORIZATION_CHALLENGES_PATH,
  PRODUCT_OWNER_GITHUB_AUTHORIZATION_COMPLETIONS_PATH,
  PRODUCT_OWNER_GITHUB_REPOSITORY_CANDIDATES_PATH,
  PRODUCT_OWNER_GITHUB_REPOSITORY_SELECTIONS_PATH,
} from "./product_owner_github_authorization.ts";
import {
  handleProductGithubWebhook,
  PRODUCT_GITHUB_WEBHOOK_PATH,
} from "./product_github_webhook.ts";
import {createForgeMcpGateway,FORGE_MCP_HOSTNAME} from "./forge_mcp_gateway.ts";

type Env = ProductAuthEnv & ProductPostgresEnv & {
  FORGE_NATIVE_DELEGATION_ENABLED?: string;
};

// ChatGPT keeps the only public MCP identity on mcp.ordax.com.br. The
// workers.dev hostname is a separate, path-restricted network ingress for the
// installed OrdaX MCP Runtime when the branded custom domain is unreachable
// from a device network. It reuses the same Worker, OAuth checks, PostgreSQL
// authority and handlers; it is not a second MCP server or fallback authority.
export const PRODUCT_TRUSTED_CLIENT_HOSTNAME = "ordax-mcp.ordaxsystems.workers.dev";
export const PRODUCT_OWNER_SESSION_PATH = "/v3/product/session";
export function isProductTrustedClientPath(pathname: string): boolean {
  return pathname === PRODUCT_OWNER_MCP_USAGE_PATH
    || pathname === PRODUCT_OWNER_SESSION_PATH
    || pathname === PRODUCT_DEVICE_SETUP_PATH
    || pathname === PRODUCT_DEVICE_PRESENCE_PATH
    || pathname === PRODUCT_DEVICE_CENTRAL_SESSION_PATH
    || pathname === PRODUCT_OWNER_PROJECT_SCOPE_PATH
    || pathname === PRODUCT_OWNER_PROJECT_ONBOARDING_PATH
    || pathname === PRODUCT_OWNER_PROJECT_ONBOARDING_PROJECTS_PATH
    || pathname === PRODUCT_OWNER_PROJECT_DEVICE_BINDING_INTENTS_PATH
    || pathname === PRODUCT_OWNER_GITHUB_AUTHORIZATION_CHALLENGES_PATH
    || pathname === PRODUCT_OWNER_GITHUB_AUTHORIZATION_COMPLETIONS_PATH
    || pathname === PRODUCT_OWNER_GITHUB_REPOSITORY_CANDIDATES_PATH
    || pathname === PRODUCT_OWNER_GITHUB_REPOSITORY_SELECTIONS_PATH
    || pathname === PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH
    || pathname === PRODUCT_OWNER_CENTRAL_DEV_TARGET_PATH
    || pathname === PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH
    || pathname === PRODUCT_OWNER_REMOTE_AUTHORITY_PATH
    || pathname === PRODUCT_OWNER_MCP_DEVICES_PATH
    || (pathname.startsWith(PRODUCT_OWNER_MCP_DEVICES_PATH + "/")
      && isCanonicalUuid(pathname.slice((PRODUCT_OWNER_MCP_DEVICES_PATH + "/").length)))
    || pathname === PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH
    || (pathname.startsWith(PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH + "/")
      && pathname.length > PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH.length + 1)
    || (pathname.startsWith(PRODUCT_DEVICE_TRANSPORT_PREFIX + "/")
      && pathname.length > PRODUCT_DEVICE_TRANSPORT_PREFIX.length + 1);
}

export const PRODUCT_MCP_CORE_READ_TOOLS: ReadonlySet<string> = new Set([
  "ordax_session", "ordax_profile", "ordax_targets", "ordax_action_status",
]);
const ATTESTED_DEVICE_OBSERVE_TOOLS: ReadonlySet<string> = new Set([
  "computer_access_status",
  "computer_active_window",
  "computer_processes",
  "computer_screen_info",
  "computer_windows",
]);
const ATTESTED_DEVICE_INTERACTIVE_TOOLS: ReadonlySet<string> = new Set([
  "computer_screenshot",
  "computer_focus_window",
  "computer_click",
  "computer_mouse_move",
  "computer_drag",
  "computer_launch_app",
  "computer_scroll",
  "computer_type",
  "computer_hotkey",
]);
const ATTESTED_DEVICE_FILESYSTEM_READ_TOOLS: ReadonlySet<string> = new Set([
  "computer_file_stat",
  "computer_directory_list",
  "computer_text_read",
  "computer_search",
]);
const ATTESTED_DEVICE_TEXT_EDIT_TOOLS: ReadonlySet<string> = new Set([
  "computer_text_write",
  "computer_text_patch",
  "computer_transfer_begin",
  "computer_transfer_chunk",
  "computer_transfer_status",
  "computer_transfer_commit",
  "computer_transfer_abort",
]);
const ATTESTED_DEVICE_FILESYSTEM_MUTATION_TOOLS: ReadonlySet<string> = new Set([
  "computer_directory_create",
  "computer_path_move",
  "computer_path_remove",
]);
const ATTESTED_DEVICE_CLIPBOARD_TOOLS: ReadonlySet<string> = new Set([
  "computer_clipboard_read",
  "computer_clipboard_write",
]);
const ATTESTED_DEVICE_PROCESS_TOOLS: ReadonlySet<string> = new Set([
  "computer_terminate_process",
]);
const ATTESTED_DEVICE_NATIVE_EXECUTION_TOOLS: ReadonlySet<string> = new Set([
  "computer_terminal_exec",
  "computer_process_start",
  "computer_process_status",
  "computer_process_list",
  "computer_process_logs",
  "computer_process_write_stdin",
  "computer_process_stop",
]);
const ATTESTED_DEVICE_ACTION_TOOLS: ReadonlySet<string> = new Set([
  "ordax_surface_status",
  "ordax_surface_open",
  "forge_status",
  ...ATTESTED_DEVICE_OBSERVE_TOOLS,
  ...ATTESTED_DEVICE_INTERACTIVE_TOOLS,
  ...ATTESTED_DEVICE_FILESYSTEM_READ_TOOLS,
  ...ATTESTED_DEVICE_TEXT_EDIT_TOOLS,
  ...ATTESTED_DEVICE_FILESYSTEM_MUTATION_TOOLS,
  ...ATTESTED_DEVICE_CLIPBOARD_TOOLS,
  ...ATTESTED_DEVICE_PROCESS_TOOLS,
  ...ATTESTED_DEVICE_NATIVE_EXECUTION_TOOLS,
]);
const ATTESTED_PROJECT_ARTIFACT_TOOLS: ReadonlySet<string> = new Set(["artifacts_list", "artifact_preview"]);
export const ATTESTED_PROJECT_NATIVE_TOOLS: ReadonlySet<string> = new Set([
  "terminal_exec", "process_start", "process_status", "process_list",
  "process_logs", "process_write_stdin", "process_stop",
]);
const ATTESTED_PROJECT_BROWSER_TOOLS: ReadonlySet<string> = new Set([
  "browser_status", "browser_list", "browser_tabs", "browser_snapshot", "browser_screenshot",
  "browser_start", "browser_tab_open", "browser_navigate", "browser_click", "browser_type", "browser_stop",
]);
const ATTESTED_PROJECT_BLENDER_TOOLS: ReadonlySet<string> = new Set([
  "blender_status", "blender_scene_snapshot", "blender_object_inspect",
  "blender_modeling_schema", "blender_start", "blender_transform",
  "blender_create_primitive", "blender_rig_create", "blender_apply_material",
  "blender_save",
]);
const ATTESTED_REPOSITORY_CATALOG_TOOLS: ReadonlySet<string> = new Set(["repository_catalog"]);
const ATTESTED_PROJECT_CONTINUITY_TOOLS: ReadonlySet<string> = new Set([
  "project_briefing", "continuity_state", "continuity_update", "handoff_create", "handoff_get",
]);
const ATTESTED_SPECIAL_TOOLS: ReadonlySet<string> = new Set([
  ...ATTESTED_REPOSITORY_CATALOG_TOOLS, ...ATTESTED_PROJECT_CONTINUITY_TOOLS,
]);
export const PRODUCT_MCP_DIRECT_TOOLS: ReadonlySet<string> = new Set([
  ...PRODUCT_MCP_CORE_READ_TOOLS,
  "ordax_action_list",
  ...ATTESTED_DEVICE_ACTION_TOOLS,
  ...ATTESTED_PROJECT_NATIVE_TOOLS,
  ...ATTESTED_PROJECT_ARTIFACT_TOOLS,
  ...ATTESTED_PROJECT_BLENDER_TOOLS,
  ...ATTESTED_PROJECT_BROWSER_TOOLS,
  ...ATTESTED_SPECIAL_TOOLS,
]);
type ReadHandlers = Pick<OrdaxMcpHandlers, "session" | "targets" | "getAction" | "recordUsage" | "usageFingerprintKey">;
function respond(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}
function resourceMetadata(origin: string, issuer: string) {
  return {
    resource: origin + "/mcp",
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: ["openid", "email", "offline_access"],
  };
}

type McpRoutingHint = Readonly<{
  toolName: string;
  explicitNonNullSpace: boolean;
  // Correlation intent only. Runtime attestation + signed native client are
  // checked independently before this becomes retry-correlation authority.
  nativeSessionRequested: boolean;
}>;

async function mcpRoutingHint(request: Request): Promise<McpRoutingHint | null> {
  if (request.method !== "POST") return null;
  // Do not eagerly buffer an unbounded client body just to identify a tool.
  // Reuse the same stream reader and limit as the downstream JSON-RPC parser.
  const body = await readBoundedJsonObject(request.clone(), MAX_MCP_REQUEST_BYTES);
  // A malformed tool request must not open an Owner challenge or enter
  // attested-session resolution before the JSON-RPC dispatcher rejects it.
  if (!validMcpToolCallEnvelope(body)) return null;
  const name = body.params.name;
  if (typeof name !== "string") return null;
  const args = body.params.arguments;
  const meta = body.params._meta;
  return {
    toolName: name,
    nativeSessionRequested: Boolean(meta && typeof meta === "object"
      && !Array.isArray(meta) && Object.hasOwn(meta, "ordax/native-session")),
    // Device-scoped commands never inherit a model-supplied Space. Detect
    // that denial without creating an Owner challenge for an impossible call.
    // Project-scoped commands still resolve their Space via the canonical RPC.
    explicitNonNullSpace: args !== null && typeof args === "object"
      && !Array.isArray(args) && Object.hasOwn(args, "space_id")
      && (args as Record<string, unknown>).space_id !== null,
  };
}

/** Session recovery is only coordination. A device remains trusted exclusively
 * after the canonical PostgreSQL binding has been confirmed by that Runtime.
 * A missing, invalid or revoked OAuth/session identity never triggers recovery.
 */
type OwnerWaitingResolution = Readonly<{
  ok: false;
  error: "central_session_owner_selection_required";
  challenge_id?: string;
}>;

type SessionRecoveryDependencies = Readonly<{
  resolve?: typeof resolveCentralSessionFromMcp;
  listRecentActions?: typeof listRecentProductMcpActions;
  open?: typeof openCentralSessionFromMcp;
  wait?: (milliseconds: number) => Promise<void>;
  scheduleWake?: (wake: Promise<void>) => void;
}>;

// The Runtime schedules Central attestation from the existing Product heartbeat,
// which runs every 20 seconds; its five-second min_poll_seconds is only a floor,
// NOT a five-second poll cadence. A confirmation may also take up to eight
// seconds of device HTTP work. Cover a full heartbeat plus network/scheduler
// margin without increasing idle SQL traffic or weakening device attestation.
// This is a finite request-local wait, never an authorization grace period.
// Public, bounded remediation codes. They explain why a trusted session was
// not established, but never grant a device or dispatch an action.
const CENTRAL_SESSION_REMEDIATION_ERRORS: ReadonlySet<string> = new Set([
  "central_device_offline",
  "central_device_runtime_not_ready",
  "central_session_marker_required",
  "central_device_target_missing",
  "central_device_target_ambiguous",
  "central_session_owner_selection_required",
  "central_owner_selection_in_progress",
  "central_session_revoked",
  "central_session_target_mismatch",
  "central_session_unavailable",
]);
// Preserve 32s of Runtime attestation. Early 2s checks remain responsive;
// later 4s checks cut the maximum idle recovery SQL reads from 16 to 10.
const SESSION_CONFIRMATION_DELAYS_MS = [2000, 2000, 2000, 2000, 4000, 4000, 4000, 4000, 4000, 4000] as const;
function waitForSessionConfirmation(milliseconds: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

export async function resolveOrBootstrapAttestedSession(
  request: Request,
  env: Env,
  deps: SessionRecoveryDependencies = {},
): Promise<Awaited<ReturnType<typeof resolveCentralSessionFromMcp>> | OwnerWaitingResolution> {
  const resolve = deps.resolve ?? resolveCentralSessionFromMcp;
  let result = await resolve(request.clone(), env);
  if (result.ok || result.error !== "central_session_unbound") return result;

  // This is the same device-confirmed challenge normally opened by ordax_session.
  // PostgreSQL chooses an eligible target; no device_id from MCP arguments is used.
  const opened = await (deps.open ?? openCentralSessionFromMcp)(
    request.clone(), env,
    ...(deps.scheduleWake ? [{ scheduleWake: deps.scheduleWake }] : []),
  );
  if (!opened.ok) {
    const failed: unknown = await opened.clone().json().catch(() => null);
    const code = failed && typeof failed === "object" && !Array.isArray(failed)
      ? (failed as Record<string, unknown>).error : null;
    return typeof code === "string" && CENTRAL_SESSION_REMEDIATION_ERRORS.has(code)
      ? { ok: false as const, error: code }
      : result;
  }
  const payload: unknown = await opened.clone().json().catch(() => null);
  if (!payload || typeof payload !== "object" || (payload as Record<string, unknown>).ok !== true) {
    return result;
  }
  // MCP may request a ticket, but only a separately signed Owner can choose
  // the target; do not infer a PC from MCP arguments or wait on Owner consent.
  if ((payload as Record<string, unknown>).status === "awaiting_owner") {
    const challengeId = (payload as Record<string, unknown>).challenge_id;
    // A challenge UUID is only an Owner-visible correlation reference, never
    // an access grant or the private ChatGPT session marker/hash.
    return { ok: false as const, error: "central_session_owner_selection_required",
      ...(isCanonicalUuid(challengeId) ? { challenge_id: challengeId } : {}),
    };
  }
  // The challenge can be confirmed between the first resolve and the open RPC.
  // The opened response is only a hint; authority STILL requires a fresh,
  // client/session-scoped PostgreSQL resolve before any action is dispatched.
  if ((payload as Record<string, unknown>).status === "bound") {
    result = await resolve(request.clone(), env);
    if (result.ok || result.error !== "central_session_unbound") return result;
  }
  const wait = deps.wait ?? waitForSessionConfirmation;
  for (const delayMs of SESSION_CONFIRMATION_DELAYS_MS) {
    await wait(delayMs);
    result = await resolve(request.clone(), env);
    if (result.ok || result.error !== "central_session_unbound") return result;
  }
  // No grant, device target or operation is inferred from a pending challenge.
  return { ok: false as const, error: "central_session_pending" };
}

/** Injecting read handlers or a narrower tool projection is an internal test/composition seam, never an HTTP option. */
export function createCanonicalProductMcpGateway(
  env: Env,
  providedReads: ReadHandlers | undefined = undefined,
  discoveryFetch: typeof fetch = fetch,
  allowedTools: ReadonlySet<string> = PRODUCT_MCP_DIRECT_TOOLS,
  recoveryDependencies: SessionRecoveryDependencies = {},
  postgresReadiness: typeof checkCanonicalProductPostgresReadiness = checkCanonicalProductPostgresReadiness,
) {
  return async (
    request: Request,
    context?: { waitUntil(promise: Promise<unknown>): void },
  ): Promise<Response> => {
    const url = new URL(request.url);
    if (url.hostname === FORGE_MCP_HOSTNAME) {
      return createForgeMcpGateway(env)(request);
    }
    if (url.hostname === PRODUCT_TRUSTED_CLIENT_HOSTNAME && !isProductTrustedClientPath(url.pathname)) {
      return respond({ ok: false, error: "not_found" }, 404);
    }
    // GitHub webhook is intentionally NOT in the workers.dev trusted-client
    // allowlist. Only the canonical branded ingress can reach this signed path.
    if (url.pathname === PRODUCT_GITHUB_WEBHOOK_PATH) {
      return handleProductGithubWebhook(request, env);
    }
    const metadata = url.pathname === "/.well-known/oauth-protected-resource";
    if (request.method === "GET" && url.pathname === "/health") {
      return respond({
        ok: true, service: "ordax-platform-mcp",
        mode: "attested-device-control",
        conversation_topology: "user_chatgpt_direct",
        model_relay: false,
        auth_configured: productAuthConfigured(env),
        postgres_configured: productPostgresConfigured(env),
        supports_attested_remote_reads: true,
        supports_remote_actions: true,
      });
    }
    if (request.method === "GET" && url.pathname === "/ready") {
      if (!productAuthConfigured(env) || !productPostgresConfigured(env)) {
        return respond({
          ok: false, service: "ordax-platform-mcp", oauth_discovery_ready: false,
          postgres_ready: null,
          conversation_topology: "user_chatgpt_direct", model_relay: false,
          supports_attested_remote_reads: false,
          supports_remote_actions: false, error: "platform_mcp_unconfigured",
        }, 503);
      }
      const discovery = await checkCanonicalProductOAuthDiscovery(String(env.PRODUCT_AUTH_ISSUER), discoveryFetch);
      // OAuth metadata alone is NOT database readiness. During the Hyperdrive
      // outage, discovery was healthy while all target/heartbeat SQL failed.
      // Do not add a second connection authority or synthesize device state.
      const postgres = discovery.ok ? await postgresReadiness(env) : null;
      const ready = discovery.ok && postgres?.ok === true;
      return respond({
        ok: ready, service: "ordax-platform-mcp",
        oauth_discovery_ready: discovery.ok,
        postgres_ready: postgres?.ok ?? null,
        conversation_topology: "user_chatgpt_direct",
        model_relay: false,
        supports_attested_remote_reads: ready,
        supports_remote_actions: ready,
        ...(discovery.error ? { error: discovery.error } : {}),
        ...(discovery.upstream_http_status !== undefined ? { upstream_http_status: discovery.upstream_http_status } : {}),
        ...(discovery.failure_stage ? { failure_stage: discovery.failure_stage } : {}),
        ...(postgres?.error ? { error: postgres.error } : {}),
        ...(postgres?.failure_stage ? { postgres_failure_stage: postgres.failure_stage } : {}),
      }, ready ? 200 : 503);
    }
    if (request.method === "GET" && metadata) {
      if (!productAuthConfigured(env)) return respond({ ok: false, error: "product_auth_unconfigured" }, 503);
      return respond(resourceMetadata(url.origin, String(env.PRODUCT_AUTH_ISSUER)));
    }
    if (request.method === "GET" && url.pathname === PRODUCT_OWNER_SESSION_PATH) {
      // Studio owner validation shares the same signed Product identity boundary
      // as enrollment. It does not grant MCP client permissions or remote actions.
      return productOwnerAccountSession(request, env);
    }
    if (url.pathname === PRODUCT_OWNER_MCP_USAGE_PATH) {
      return handleProductOwnerMcpUsageRead(request, env);
    }
    if (url.pathname === PRODUCT_DEVICE_SETUP_PATH) {
      return handleProductDeviceSetup(request, env);
    }
    if (url.pathname === PRODUCT_DEVICE_PRESENCE_PATH) {
      // Same PostgreSQL device identity as MCP targets; never the legacy D1 writer.
      return handleProductDevicePresence(request, env);
    }
    if (url.pathname === PRODUCT_DEVICE_CENTRAL_SESSION_PATH) {
      return handleProductDeviceCentralSession(request, env);
    }
    if (url.pathname.startsWith(PRODUCT_DEVICE_TRANSPORT_PREFIX + "/")) {
      return handleProductDeviceTransport(request, env, context);
    }
    if (url.pathname === PRODUCT_OWNER_PROJECT_SCOPE_PATH) {
      return handleProductOwnerProjectScope(request, env);
    }
    if (url.pathname === PRODUCT_OWNER_PROJECT_ONBOARDING_PATH
        || url.pathname === PRODUCT_OWNER_PROJECT_ONBOARDING_PROJECTS_PATH
        || url.pathname === PRODUCT_OWNER_PROJECT_DEVICE_BINDING_INTENTS_PATH) {
      return handleProductOwnerProjectOnboarding(request, env);
    }
    if (url.pathname === PRODUCT_OWNER_GITHUB_AUTHORIZATION_CHALLENGES_PATH
        || url.pathname === PRODUCT_OWNER_GITHUB_AUTHORIZATION_COMPLETIONS_PATH
        || url.pathname === PRODUCT_OWNER_GITHUB_REPOSITORY_CANDIDATES_PATH
        || url.pathname === PRODUCT_OWNER_GITHUB_REPOSITORY_SELECTIONS_PATH) {
      return handleProductOwnerGithubAuthorization(request, env);
    }
    if (url.pathname === PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH
        || url.pathname === PRODUCT_OWNER_CENTRAL_DEV_TARGET_PATH
        || url.pathname === PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH
        || url.pathname === PRODUCT_OWNER_REMOTE_AUTHORITY_PATH
        || url.pathname === PRODUCT_OWNER_MCP_DEVICES_PATH
        || url.pathname.startsWith(PRODUCT_OWNER_MCP_DEVICES_PATH + "/")
        || url.pathname === PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH
        || url.pathname.startsWith(PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH + "/")) {
      return handleProductOwnerGrantAdmin(request, env,
        context ? { scheduleWake: (wake: Promise<void>) => context.waitUntil(wake) } : {});
    }
    if (url.pathname === "/mcp") {
      // This closure belongs only to this HTTP request. Its clones share the
      // same verified bearer, never another chat's token or auth outcome.
      const authenticate = requestScopedProductMcpAuthenticator(request, env);
      // The same request-scoped signed proof serves the MCP dispatcher and
      // Central session coordination. PostgreSQL resolution remains fresh on
      // every resolve/open and no OAuth decision crosses request boundaries.
      const resolveSession: typeof resolveCentralSessionFromMcp =
        recoveryDependencies.resolve ??
        ((candidate, candidateEnv) => resolveCentralSessionFromMcp(candidate, candidateEnv, { authenticate }));
      const openSession: typeof openCentralSessionFromMcp =
        recoveryDependencies.open ??
        ((candidate, candidateEnv, options) =>
          openCentralSessionFromMcp(candidate, candidateEnv, { ...options, authenticate }));
      const reads = providedReads ?? createCanonicalProductMcpReadHandlers(env, { authenticate });
      const deniedHandlers: OrdaxMcpHandlers = {
        ...reads,
        createAction: async () => respond({ ok: false, error: "trusted_operation_required" }, 403),
      };
      const routingHint = await mcpRoutingHint(request);
      const toolName = routingHint?.toolName ?? null;
      // This single request-owned scheduler serves SQL-committed action wakes
      // and device-attested session challenges. No second queue or authority.
      const wakeDependencies = context
        ? { scheduleWake: (wake: Promise<void>) => context.waitUntil(wake), authenticate }
        : { authenticate };
      // ordax_session is already a safe authenticated read tool. Its only new
      // side effect is opening/renewing a short-lived, server-selected device
      // challenge from the hidden provider correlation marker. This is session
      // coordination for the direct MCP path; it is not Central model relay.
      let sessionDeviceBinding: OrdaxMcpHandlers["sessionDeviceBinding"];
      let sessionOwnerSelection: OrdaxMcpHandlers["sessionOwnerSelection"];
      if (toolName === "ordax_session") {
        // An already-attested binding needs one fresh SQL read, not an extra
        // challenge/open RPC. The resolver revalidates OAuth and grants.
        const resolveBinding = async (): Promise<boolean> => {
          try {
            const resolved = await resolveSession(
              request.clone(), env,
            );
            if (!resolved.ok) return false;
            sessionDeviceBinding = Object.freeze({
              state: "bound",
              device_id: resolved.deviceId,
              attested: true,
              routing_authority: "central_conversation_binding",
              dispatch_target_resolved: true,
              capability_authorization: "checked_per_action",
            });
            return true;
          } catch {
            return false;
          }
        };
        if (!(await resolveBinding())) {
          let openedBound = false;
          try {
            const opened = await openSession(
              request.clone(), env, wakeDependencies,
            );
            if (opened.ok) {
              const raw = await opened.json() as Record<string, unknown>;
              openedBound = raw?.ok === true && raw.status === "bound";
              const challengeId = raw?.challenge_id;
              const expiresAt = raw?.expires_at;
              if (raw?.ok === true && raw.status === "awaiting_owner"
                  && isCanonicalUuid(challengeId) && typeof expiresAt === "string"
                  && Number.isFinite(Date.parse(expiresAt))
                  && Date.parse(expiresAt) > Date.now()) {
                // Owner choice is only a correlation, never authority.
                sessionOwnerSelection = Object.freeze({
                  state: "awaiting_owner", challenge_id: challengeId.toLowerCase(),
                  expires_at: expiresAt, selection_location: "ordax_owner",
                  owner_confirmation_required: true, action_dispatched: false,
                });
              }
            }
          } catch { /* missing/malformed opening result never becomes authority */ }
          // A bound opening is only a hint; recheck the PostgreSQL authority.
          if (openedBound) await resolveBinding();
        }
      }

      let verifiedActionDeviceId: string | undefined;
      let verifiedNativeRetryClientId: string | undefined;
      let handlers: OrdaxMcpHandlers = sessionDeviceBinding
        ? { ...deniedHandlers, sessionDeviceBinding }
        : sessionOwnerSelection
          ? { ...deniedHandlers, sessionOwnerSelection }
          : deniedHandlers;
      if (toolName === "ordax_action_list" && allowedTools.has(toolName)) {
        const historyRequest = request.clone();
        handlers = {
          ...handlers,
          async listRecentActions(query) {
            try {
              const binding = await resolveSession(
                historyRequest, env,
              );
              if (!binding.ok) {
                const unavailable = ["central_session_unavailable", "product_postgres_unconfigured"]
                  .includes(binding.error);
                return respond({ ok: false, error: unavailable
                  ? "product_action_history_unavailable" : "product_action_history_binding_required" },
                unavailable ? 503 : 403);
              }
              const result = await (recoveryDependencies.listRecentActions ?? listRecentProductMcpActions)(
                env, { ownerUserId: binding.ownerUserId, clientId: binding.clientId,
                  deviceId: binding.deviceId, ...query },
              );
              if (result?.ok !== true) {
                return result?.error === "product_owner_auth_ineligible"
                  ? respond({ ok: false, error: "product_owner_auth_ineligible" }, 403)
                  : respond({ ok: false, error: "product_action_history_invalid_response" }, 502);
              }
              return respond({ ok: true, device_id: binding.deviceId, actions: result.actions });
            } catch {
              return respond({ ok: false, error: "product_action_history_unavailable" }, 503);
            }
          },
        };
      }
      if (toolName && allowedTools.has(toolName)
        && ATTESTED_DEVICE_ACTION_TOOLS.has(toolName)
        && routingHint?.explicitNonNullSpace) {
        // The canonical device handler accepts space_id=null only. Reject
        // the explicit foreign/invalid Space at the authenticated JSON-RPC
        // boundary, before any session bootstrap or Owner selection. This
        // does not authorize the call or enqueue an action.
        handlers = {
          ...reads,
          createAction: async () => respond({
            ok: false, error: "product_device_action_invalid",
          }, 400),
        };
      } else if (toolName && allowedTools.has(toolName)
        && (ATTESTED_DEVICE_ACTION_TOOLS.has(toolName) || ATTESTED_PROJECT_NATIVE_TOOLS.has(toolName)
          || ATTESTED_PROJECT_ARTIFACT_TOOLS.has(toolName)
          || ATTESTED_PROJECT_BLENDER_TOOLS.has(toolName) || ATTESTED_PROJECT_BROWSER_TOOLS.has(toolName)
          || ATTESTED_SPECIAL_TOOLS.has(toolName))) {
        let trusted: AttestedMcpDevice | null = null;
        let pending = false;
        let trustFailure: string | null = null;
        let ownerChallengeId: string | null = null;
        try {
          const resolved = await resolveOrBootstrapAttestedSession(
            request.clone(), env, {
              ...recoveryDependencies, ...wakeDependencies,
              resolve: resolveSession, open: openSession,
            },
          );
          if (resolved.ok) {
            trusted = Object.freeze({
              ownerUserId: resolved.ownerUserId,
              clientId: resolved.clientId,
              deviceId: resolved.deviceId,
            });
            verifiedActionDeviceId = trusted.deviceId;
            // The SAME PostgreSQL Forge OAuth consent/instance authority
            // and Runtime-attested device resolved this native correlation.
            // The nonce alone never grants a retry or execution authority.
            if (routingHint?.nativeSessionRequested
              && env.FORGE_NATIVE_DELEGATION_ENABLED === "enabled")
              verifiedNativeRetryClientId = trusted.clientId;
          } else {
            pending = resolved.error === "central_session_pending";
            if (CENTRAL_SESSION_REMEDIATION_ERRORS.has(resolved.error)) {
              trustFailure = resolved.error;
              if (resolved.error === "central_session_owner_selection_required"
                  && "challenge_id" in resolved && isCanonicalUuid(resolved.challenge_id)) {
                ownerChallengeId = resolved.challenge_id;
              }
            }
          }
        } catch {
          // No attested PostgreSQL resolution is possible; never present a
          // transient authority outage as a missing grant or trust bypass.
          trusted = null;
          trustFailure = "central_session_unavailable";
        }
        handlers = {
          ...reads,
          createAction: pending
            ? async () => respond({ ok: false, error: "central_session_pending" }, 409)
            : trustFailure
              ? async () => respond({ ok: false, error: trustFailure,
                  ...(trustFailure === "central_session_owner_selection_required" && ownerChallengeId
                    ? { challenge_id: ownerChallengeId, action_dispatched: false } : {}),
                }, trustFailure === "central_session_unavailable" ? 503 : 409)
              : (ATTESTED_PROJECT_NATIVE_TOOLS.has(toolName) || ATTESTED_PROJECT_ARTIFACT_TOOLS.has(toolName)
                || ATTESTED_PROJECT_BLENDER_TOOLS.has(toolName) || ATTESTED_PROJECT_BROWSER_TOOLS.has(toolName))
              ? createAttestedProjectActionHandler(env, trusted, wakeDependencies)
              : ATTESTED_PROJECT_CONTINUITY_TOOLS.has(toolName)
                ? createAttestedProjectContinuityHandler(env, trusted, wakeDependencies)
                : ATTESTED_REPOSITORY_CATALOG_TOOLS.has(toolName)
                  ? createAttestedRepositoryCatalogHandler(env, trusted, wakeDependencies)
                  : createAttestedDeviceActionHandler(env, trusted, wakeDependencies),
        };
      }
      return handleOrdaxMcp(request, {
        ...handlers,
        verifiedActionDeviceId,
        verifiedNativeRetryClientId,
        waitForCompletion: (deviceId, requestId, remainingMs) =>
          waitProductActionCompletion(env, deviceId, requestId, remainingMs),
      }, allowedTools, context);
    }
    return respond({ ok: false, error: "not_found" }, 404);
  };
}

export default {
  fetch(
    request: Request,
    env: Env,
    context?: { waitUntil(promise: Promise<unknown>): void },
  ): Promise<Response> {
    return createCanonicalProductMcpGateway(env)(request, context);
  },
  scheduled(_controller: { scheduledTime: number; cron: string }, env: Env, context: { waitUntil(promise: Promise<unknown>): void }): void {
    context.waitUntil(pruneProductMcpUsage(env).catch(() => {
      // The database adapter already emits a bounded diagnostic. Never log
      // owner ids, request fingerprints, SQL, or connection details here.
      console.error(JSON.stringify({ event: "product_mcp_usage_cleanup_failed" }));
    }));
  },
};

