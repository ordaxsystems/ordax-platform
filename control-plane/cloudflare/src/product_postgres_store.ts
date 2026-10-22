import { openPostgresSession } from "./data_postgres_driver.ts";
import { encodePostgresTextArrayLiteral, InvalidPostgresTextArrayError } from "./product_postgres_text_array.ts";
import {
  canonicalRemoteClient,
  canonicalRemoteGrantGroup,
  isCanonicalUuid,
  type RemoteClientKind,
  type RemoteGrantGroupInput,
} from "./product_remote_grant_contract.ts";

type JsonObject = Record<string, unknown>;

export interface ProductPostgresEnv {
  POSTGRES?: Hyperdrive;
}

export type ProductRemoteJob = {
  request_id: string;
  device_id: string;
  project_id: string | null;
  capability: string;
  payload: JsonObject;
  payload_sha256: string;
  effect_id: string;
  attempt_id: string;
  lease_id: string;
  execution_epoch: number;
  agent_instance_id: string;
  boot_id: string;
  lease_expires_at: string;
};

export type ProductActionEnqueueResult = {
  ok: boolean;
  replayed?: boolean;
  request_id?: string;
  effect_id?: string;
  status?: string;
  error?: string;
};

export type ProductActionClaimResult = {
  ok: boolean;
  job: ProductRemoteJob | null;
  error?: string;
};

export class ProductPostgresError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number) {
    super(code);
    this.name = "ProductPostgresError";
    this.code = code;
    this.status = status;
  }
}

type SafePostgresFailure = {
  event: "product_postgres_failure";
  rpc: string;
  name: string;
  code: string | null;
  errno: string | number | null;
  syscall: string | null;
  cause_name: string | null;
  cause_code: string | null;
  classification: string;
  signals: string[];
};

const POSTGRES_FAILURE_SIGNAL_MARKERS = Object.freeze([
  ["server_connection_attempt", "server connection attempt"],
  ["pool_acquire", "connection from the pool"],
  ["server_closed_connection", "server return error and closed connection"],
  ["database_connect", "failed to connect to the provided database"],
  ["tls", "tls"],
  ["certificate", "cert"],
  ["timeout", "timeout"],
  ["connection_refused", "connection_refused"],
  ["connection_reset", "connection reset"],
  ["authentication", "authentication"],
  ["prepared_statement", "prepared statement"],
  ["protocol", "protocol"],
  ["internal_error", "internal error"],
  ["pg_connection_terminated_unexpectedly", "connection terminated unexpectedly"],
  ["pg_connection_terminated", "connection terminated"],
  ["pg_client_connection_error", "client has encountered a connection error"],
  ["pg_client_closed", "client was closed and is not queryable"],
  ["pg_cross_request_io", "cannot perform i/o on behalf of a different request"],
  ["pg_client_reused", "client has already been connected"],
] as const);

function postgresFailureMessage(error: unknown): string {
  const record = error && typeof error === "object" ? error as Record<string, unknown> : {};
  return typeof record.message === "string" ? record.message.toLowerCase() : "";
}

function postgresFailureSignals(error: unknown): string[] {
  const message = postgresFailureMessage(error);
  return POSTGRES_FAILURE_SIGNAL_MARKERS
    .filter(([, marker]) => message.includes(marker))
    .map(([signal]) => signal);
}

function classifyPostgresFailure(error: unknown): string {
  const message = postgresFailureMessage(error);
  if (message.includes("failed to acquire a connection from the pool")) return "hyperdrive_pool_acquire_failed";
  if (message.includes("server connection attempt failed") && message.includes("connection_refused")) return "hyperdrive_origin_connection_refused";
  if (message.includes("server connection attempt failed")) return "hyperdrive_server_connection_failed";
  if (message.includes("server return error and closed connection")) return "hyperdrive_server_closed_connection";
  if (message.includes("failed to connect to the provided database")) return "hyperdrive_database_connect_failed";
  if (message.includes("internal error")) return "hyperdrive_internal_error";
  if (message.includes("connection terminated unexpectedly")) return "pg_connection_terminated_unexpectedly";
  if (message.includes("connection terminated")) return "pg_connection_terminated";
  if (message.includes("client has encountered a connection error")) return "pg_client_connection_error";
  if (message.includes("client was closed and is not queryable")) return "pg_client_closed";
  if (message.includes("cannot perform i/o on behalf of a different request")) return "pg_cross_request_io";
  if (message.includes("client has already been connected")) return "pg_client_reused";
  if (message.includes("bad hostname")) return "hyperdrive_bad_hostname";
  if (message.includes("cannot connect to the host")) return "hyperdrive_origin_unreachable";
  if (message.includes("tls handshake failed")) return "hyperdrive_tls_handshake_failed";
  if (message.includes("cert validation failed")) return "hyperdrive_tls_cert_validation_failed";
  if (message.includes("password authentication failed") || message.includes("authentication failed")) return "origin_authentication_failed";
  if (message.includes("connection refused")) return "origin_connection_refused";
  if (message.includes("connection reset")) return "origin_connection_reset";
  if (message.includes("timeout")) return "connection_timeout";
  if (message.includes("prepared statement")) return "prepared_statement_failure";
  if (message.includes("protocol")) return "protocol_failure";
  return "unclassified";
}

function boundedDiagnostic(value: unknown, max = 80): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= max
    ? value : null;
}

export function safePostgresFailure(error: unknown, rpc: string): SafePostgresFailure {
  const record = error && typeof error === "object" ? error as Record<string, unknown> : {};
  const cause = record.cause && typeof record.cause === "object"
    ? record.cause as Record<string, unknown> : {};
  return {
    event: "product_postgres_failure",
    rpc,
    name: boundedDiagnostic(record.name) ?? (error instanceof Error ? error.name : "UnknownError"),
    code: boundedDiagnostic(record.code),
    errno: typeof record.errno === "number" ? record.errno : boundedDiagnostic(record.errno),
    syscall: boundedDiagnostic(record.syscall),
    cause_name: boundedDiagnostic(cause.name),
    cause_code: boundedDiagnostic(cause.code),
    classification: classifyPostgresFailure(error),
    signals: postgresFailureSignals(error),
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const RPC_SPECS = {
  // Staged read-only RPC: remains unavailable until the separately governed
  // PostgreSQL proposal is applied. No new grant authority is created here.
  ordax_verify_project_workspace_resource_v1: {
    keys: ["p_owner_user_id", "p_actor_id", "p_client_id",
      "p_workspace_session_id", "p_lab_project_id",
      "p_device_id", "p_resource_id"],
    casts: ["uuid", "uuid", "uuid", "text", "text", "uuid", "text"],
  },
  ordax_orchestrator_read_authorization_v1: {
    keys: ["p_device_id", "p_request_id", "p_effect_id", "p_attempt_id",
      "p_lease_id", "p_execution_epoch", "p_agent_instance_id", "p_boot_id"],
    casts: ["uuid", "uuid", "uuid", "uuid", "uuid", "bigint", "uuid", "text"],
  },
  ordax_enqueue_product_action_v1: {
    keys: [
      "p_owner_user_id",
      "p_space_id",
      "p_project_id",
      "p_device_id",
      "p_client_kind",
      "p_client_id",
      "p_capability",
      "p_access_mode",
      "p_payload",
      "p_idempotency_key",
      "p_expires_at",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "text", "text", "text", "text", "jsonb", "text", "timestamptz"],
  },
  ordax_claim_product_action_v1: {
    keys: ["p_device_id", "p_agent_instance_id", "p_boot_id", "p_lease_seconds"],
    casts: ["uuid", "uuid", "text", "integer"],
  },
  ordax_start_product_action_v1: {
    keys: [
      "p_device_id",
      "p_request_id",
      "p_effect_id",
      "p_attempt_id",
      "p_lease_id",
      "p_execution_epoch",
      "p_agent_instance_id",
      "p_boot_id",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "uuid", "bigint", "uuid", "text"],
  },
  ordax_renew_product_action_lease_v1: {
    keys: [
      "p_device_id",
      "p_request_id",
      "p_effect_id",
      "p_attempt_id",
      "p_lease_id",
      "p_execution_epoch",
      "p_agent_instance_id",
      "p_boot_id",
      "p_lease_seconds",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "uuid", "bigint", "uuid", "text", "integer"],
    resultCast: "text",
  },
  ordax_progress_product_action_v1: {
    keys: [
      "p_device_id",
      "p_request_id",
      "p_effect_id",
      "p_attempt_id",
      "p_lease_id",
      "p_execution_epoch",
      "p_agent_instance_id",
      "p_boot_id",
      "p_stage",
      "p_message",
      "p_progress_percent",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "uuid", "bigint", "uuid", "text", "text", "text", "smallint"],
  },
  ordax_report_product_action_v1: {
    keys: [
      "p_device_id",
      "p_request_id",
      "p_effect_id",
      "p_attempt_id",
      "p_lease_id",
      "p_execution_epoch",
      "p_agent_instance_id",
      "p_boot_id",
      "p_report_id",
      "p_status",
      "p_result",
      "p_result_sha256",
      "p_error_code",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "uuid", "bigint", "uuid", "text", "uuid", "text", "jsonb", "text", "text"],
  },
  ordax_bind_product_action_runtime_provenance_v1: {
    keys: [
      "p_device_id",
      "p_request_id",
      "p_effect_id",
      "p_attempt_id",
      "p_lease_id",
      "p_execution_epoch",
      "p_agent_instance_id",
      "p_boot_id",
      "p_runtime_kind",
      "p_agent_version",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "uuid", "bigint", "uuid", "text", "text", "text"],
  },
  ordax_get_product_action_v1: {
    keys: ["p_owner_user_id", "p_client_kind", "p_client_id", "p_request_id"],
    casts: ["uuid", "text", "text", "uuid"],
  },
  ordax_replace_remote_grant_group_v1: {
    keys: [
      "p_owner_user_id", "p_space_id", "p_project_id", "p_device_id",
      "p_client_kind", "p_client_id", "p_profile_key", "p_capabilities",
      "p_access_modes", "p_valid_until",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "text", "text", "text", "text[]", "text[]", "timestamptz"],
  },
  ordax_revoke_remote_grant_group_v1: {
    keys: ["p_owner_user_id", "p_grant_group_id"],
    casts: ["uuid", "uuid"],
  },
  ordax_owner_mcp_remote_authority_v1: {
    keys: ["p_owner_user_id", "p_device_id"],
    casts: ["uuid", "uuid"],
  },
  ordax_replace_owner_mcp_grant_group_v1: {
    keys: [
      "p_owner_user_id", "p_space_id", "p_project_id", "p_device_id",
      "p_client_id", "p_profile_key", "p_capabilities", "p_access_modes",
      "p_valid_until",
    ],
    casts: ["uuid", "uuid", "uuid", "uuid", "text", "text", "text[]", "text[]", "timestamptz"],
  },
  ordax_revoke_owner_mcp_grant_group_v1: {
    keys: ["p_owner_user_id", "p_client_id", "p_grant_group_id"],
    casts: ["uuid", "text", "uuid"],
  },
  ordax_bind_central_conversation_v1: {
    keys: ["p_owner_user_id","p_client_id","p_device_id","p_space_id",
      "p_project_id","p_request_id","p_conversation_id","p_session_sha256",
      "p_expires_at"],
    casts: ["uuid","text","uuid","uuid","uuid","uuid","text","text","timestamptz"],
  },
  ordax_verify_central_conversation_v1: {
    keys: ["p_owner_user_id","p_client_id","p_device_id","p_space_id",
      "p_project_id","p_request_id","p_conversation_id","p_session_sha256"],
    casts: ["uuid","text","uuid","uuid","uuid","uuid","text","text"],
  },
  ordax_revoke_central_conversation_v1: {
    keys: ["p_owner_user_id","p_client_id","p_request_id"],
    casts: ["uuid","text","uuid"],
  },
  ordax_list_product_targets_v1: {
    keys: ["p_owner_user_id", "p_client_kind", "p_client_id"],
    casts: ["uuid", "text", "text"],
  },
  ordax_record_product_presence_v1: {
    keys: [
      "p_device_id",
      "p_online",
      "p_runtime_kind",
      "p_agent_version",
      "p_capability_digest",
      "p_force",
    ],
    casts: ["uuid", "boolean", "text", "text", "text", "boolean"],
  },
  ordax_enroll_product_device_v1: {
    keys: [
      "p_owner_user_id",
      "p_device_name",
      "p_device_kind",
      "p_channel",
      "p_token_sha256",
      "p_machine_binding_sha256",
    ],
    casts: ["uuid", "text", "text", "text", "text", "text"],
  },
  ordax_identify_product_device_v1: {
    keys: ["p_token_sha256", "p_machine_binding_sha256"],
    casts: ["text", "text"],
  },
  ordax_authenticate_product_device_v1: {
    keys: ["p_device_id", "p_token_sha256"],
    casts: ["uuid", "text"],
  },
  ordax_import_legacy_product_device_v1: {
    keys: [
      "p_device_id",
      "p_owner_user_id",
      "p_display_name",
      "p_device_kind",
      "p_channel",
      "p_token_sha256",
      "p_machine_binding_sha256",
      "p_last_seen_at",
    ],
    casts: ["uuid", "uuid", "text", "text", "text", "text", "text", "timestamptz"],
  },
} as const;

type RpcName = keyof typeof RPC_SPECS;

function configuredConnectionString(env: ProductPostgresEnv): string | null {
  const raw = (env.POSTGRES?.connectionString ?? "").trim();
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
      return null;
    }
    return raw;
  } catch {
    return null;
  }
}

export function productPostgresConfigured(env: ProductPostgresEnv): boolean {
  return configuredConnectionString(env) !== null;
}

/** An actual Hyperdrive connection and bounded, non-privileged SQL query.
 * This is the existing PostgreSQL authority, not a second health backend.
 * The returned diagnosis is public-safe; do not propagate pg exception text.
 */
export type ProductPostgresReadiness = Readonly<{
  ok: boolean;
  error: "product_postgres_unconfigured" | "product_postgres_unavailable" | null;
  failure_stage?: "connect" | "query" | "decode";
}>;
type ReadinessClient = {
  connect(): Promise<void>;
  query(sql: string): Promise<{ rows: Array<{ alive?: unknown }> }>;
  end(): Promise<void>;
};

export async function checkCanonicalProductPostgresReadiness(
  env: ProductPostgresEnv,
  createClient: (connectionString: string) => ReadinessClient =
    connectionString => openPostgresSession(connectionString),
): Promise<ProductPostgresReadiness> {
  const connectionString = configuredConnectionString(env);
  if (!connectionString) return { ok: false, error: "product_postgres_unconfigured" };
  let client: ReadinessClient | null = null;
  let phase: "connect" | "query" | "decode" = "connect";
  try {
    client = createClient(connectionString);
    await client.connect();
    phase = "query";
    const result = await client.query("select 1::int as alive");
    phase = "decode";
    if (result.rows.length !== 1 || result.rows[0]?.alive !== 1) {
      return { ok: false, error: "product_postgres_unavailable", failure_stage: phase };
    }
    return { ok: true, error: null };
  } catch (error) {
    // Public readiness remains generic. Operators need a bounded diagnostic
    // for connectivity incidents without ever logging exception messages,
    // credentials, URLs or raw PostgreSQL connection strings.
    const safe = safePostgresFailure(error, "readiness");
    console.error(JSON.stringify({
      event: "product_postgres_readiness_failure",
      phase,
      classification: safe.classification,
      signals: safe.signals,
    }));
    return { ok: false, error: "product_postgres_unavailable", failure_stage: phase };
  } finally {
    if (client) {
      try { await client.end(); } catch { /* Connection cleanup cannot mask probe outcome. */ }
    }
  }
}

function encodeRpcValue(value: unknown, cast: string): unknown {
  if (value === undefined) return null;
  if (cast === "jsonb" && value !== null) return JSON.stringify(value);
  return value;
}

async function callRpc<T>(
  env: ProductPostgresEnv,
  rpc: RpcName,
  payload: JsonObject,
): Promise<T> {
  const connectionString = configuredConnectionString(env);
  if (!connectionString) {
    throw new ProductPostgresError("product_postgres_unconfigured", 503);
  }

  const spec = RPC_SPECS[rpc];
  const args = spec.casts.map((cast, index) => `$${index + 1}::${cast}`).join(", ");
  const resultCast = "resultCast" in spec ? `::${spec.resultCast}` : "";
  const query = `select public.${rpc}(${args})${resultCast} as result`;
  const client = openPostgresSession(connectionString);

  let phase: "connect" | "query" | "decode" = "connect";
  try {
    const values = spec.keys.map((key, index) => {
      const value = encodeRpcValue(payload[key], spec.casts[index]);
      if (spec.casts[index] !== "text[]") return value;
      // Bind a canonical PostgreSQL text[] literal; the allowlisted RPC owns
      // the explicit $n::text[] cast.
      try {
        return encodePostgresTextArrayLiteral(value);
      } catch (error) {
        if (error instanceof InvalidPostgresTextArrayError) {
          throw new ProductPostgresError("product_grant_invalid", 400);
        }
        throw error;
      }
    });
    await client.connect();
    phase = "query";
    const response = await client.query(query, values);
    phase = "decode";
    const rows = response.rows;
    const row = rows[0] as { result?: T } | undefined;
    if (!row || !Object.prototype.hasOwnProperty.call(row, "result")) {
      throw new ProductPostgresError("product_postgres_invalid_response", 502);
    }
    return row.result as T;
  } catch (error) {
    if (error instanceof ProductPostgresError) throw error;
    // The client-facing response remains deliberately generic. Emit only an
    // allowlisted diagnostic envelope: never SQL, values, connection strings,
    // hostnames, credentials, messages or stacks.
    const diagnostic = safePostgresFailure(error, rpc);
    console.error(JSON.stringify({ ...diagnostic, phase }));
    // SQLSTATE 22P05 means the report contains a U+0000 character that
    // PostgreSQL JSONB cannot store. This is invalid action output, not an
    // unavailable database: retries of identical bytes can never succeed.
    if (rpc === "ordax_report_product_action_v1"
        && (diagnostic.code === "22P05" || diagnostic.cause_code === "22P05")) {
      throw new ProductPostgresError("report_result_invalid_unicode", 422);
    }
    throw new ProductPostgresError("product_postgres_unavailable", 503);
  } finally {
    try {
      await client.end();
    } catch {
      // Hyperdrive owns the upstream pool; connection cleanup must not mask
      // the result of an already-completed authority call.
    }
  }
}

export async function enqueueProductAction(
  env: ProductPostgresEnv,
  input: {
    ownerUserId: string;
    spaceId: string | null;
    projectId: string | null;
    deviceId: string;
    clientKind: RemoteClientKind;
    clientId: string;
    capability: string;
    accessMode: "read" | "write";
    payload: JsonObject;
    idempotencyKey: string;
    expiresAt: string;
  },
): Promise<ProductActionEnqueueResult> {
  // caller must derive this identity from verified credentials; never from payload
  const client = canonicalRemoteClient(input.ownerUserId, input.clientKind, input.clientId);
  if (!client || client.p_client_id === null) {
    throw new ProductPostgresError("product_action_client_identity_invalid", 400);
  }
  return callRpc<ProductActionEnqueueResult>(
    env,
    "ordax_enqueue_product_action_v1",
    {
      p_owner_user_id: input.ownerUserId,
      p_space_id: input.spaceId,
      p_project_id: input.projectId,
      p_device_id: input.deviceId,
      p_client_kind: client.p_client_kind,
      p_client_id: client.p_client_id,
      p_capability: input.capability,
      p_access_mode: input.accessMode,
      p_payload: input.payload,
      p_idempotency_key: input.idempotencyKey,
      p_expires_at: input.expiresAt,
    },
  );
}

export async function claimProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    agentInstanceId: string;
    bootId: string;
    leaseSeconds?: number;
  },
): Promise<ProductActionClaimResult> {
  return callRpc<ProductActionClaimResult>(
    env,
    "ordax_claim_product_action_v1",
    {
      p_device_id: input.deviceId,
      p_agent_instance_id: input.agentInstanceId,
      p_boot_id: input.bootId,
      p_lease_seconds: input.leaseSeconds ?? 120,
    },
  );
}

export async function startProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_start_product_action_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
  });
}

export type WorkspaceResourceVerificationInput = Readonly<{
  ownerUserId: string;
  actorId: string;
  clientId: string;
  workspaceSessionId: string;
  labProjectId: string;
  deviceId: string;
  resourceId: string;
}>;

/** Execute only the canonical PostgreSQL read-only resource verifier.
 * Caller authentication belongs to the existing Product Device transport.
 * No issuer, path lookup, grant cache, or shadow permissions table.
 */
export async function verifyProjectWorkspaceResource(
  env: ProductPostgresEnv,
  input: WorkspaceResourceVerificationInput,
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_verify_project_workspace_resource_v1", {
    p_owner_user_id: input.ownerUserId,
    p_actor_id: input.actorId,
    p_client_id: input.clientId,
    p_workspace_session_id: input.workspaceSessionId,
    p_lab_project_id: input.labProjectId,
    p_device_id: input.deviceId,
    p_resource_id: input.resourceId,
  });
}

export async function resolveOrchestratorReadAuthorization(
  env: ProductPostgresEnv,
  input: Parameters<typeof startProductAction>[1],
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_orchestrator_read_authorization_v1", {
    p_device_id: input.deviceId, p_request_id: input.requestId,
    p_effect_id: input.effectId, p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId, p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId, p_boot_id: input.bootId,
  });
}

export async function renewProductActionLease(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
    leaseSeconds?: number;
  },
): Promise<string | null> {
  return callRpc<string | null>(env, "ordax_renew_product_action_lease_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
    p_lease_seconds: input.leaseSeconds ?? 120,
  });
}

export async function progressProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
    stage: string;
    message: string | null;
    progressPercent: number | null;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_progress_product_action_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
    p_stage: input.stage,
    p_message: input.message,
    p_progress_percent: input.progressPercent,
  });
}

export async function reportProductAction(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
    reportId: string;
    status: "succeeded" | "failed" | "cancelled";
    result: JsonObject;
    resultSha256: string;
    errorCode: string | null;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_report_product_action_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
    p_report_id: input.reportId,
    p_status: input.status,
    p_result: input.result,
    p_result_sha256: input.resultSha256,
    p_error_code: input.errorCode,
  });
}

export async function bindProductActionRuntimeProvenance(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    requestId: string;
    effectId: string;
    attemptId: string;
    leaseId: string;
    executionEpoch: number;
    agentInstanceId: string;
    bootId: string;
    runtimeKind: "ordax-os" | "desktop-agent" | "mobile-client" | "other";
    agentVersion: string;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_bind_product_action_runtime_provenance_v1", {
    p_device_id: input.deviceId,
    p_request_id: input.requestId,
    p_effect_id: input.effectId,
    p_attempt_id: input.attemptId,
    p_lease_id: input.leaseId,
    p_execution_epoch: input.executionEpoch,
    p_agent_instance_id: input.agentInstanceId,
    p_boot_id: input.bootId,
    p_runtime_kind: input.runtimeKind,
    p_agent_version: input.agentVersion,
  });
}

export async function getProductAction(
  env: ProductPostgresEnv,
  input: {
    ownerUserId: string;
    clientKind: RemoteClientKind;
    clientId: string;
    requestId: string;
  },
): Promise<JsonObject | null> {
  const client = canonicalRemoteClient(input.ownerUserId, input.clientKind, input.clientId);
  if (!client || client.p_client_id === null || !isCanonicalUuid(input.requestId)) {
    throw new ProductPostgresError("product_action_identity_invalid", 400);
  }
  return callRpc<JsonObject | null>(env, "ordax_get_product_action_v1", {
    ...client,
    p_request_id: input.requestId,
  });
}

export async function recordProductPresence(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    online: boolean;
    runtimeKind: "ordax-os" | "desktop-agent" | "mobile-client" | "other" | null;
    agentVersion: string | null;
    capabilityDigest: string | null;
    force?: boolean;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_record_product_presence_v1", {
    p_device_id: input.deviceId,
    p_online: input.online,
    p_runtime_kind: input.runtimeKind,
    p_agent_version: input.agentVersion,
    p_capability_digest: input.capabilityDigest,
    p_force: input.force ?? false,
  });
}

export async function enrollProductDevice(
  env: ProductPostgresEnv,
  input: {
    ownerUserId: string;
    deviceName: string;
    deviceKind: "desktop" | "laptop" | "mobile" | "server" | "other";
    channel: "stable" | "development";
    tokenSha256: string;
    machineBindingSha256: string;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_enroll_product_device_v1", {
    p_owner_user_id: input.ownerUserId,
    p_device_name: input.deviceName,
    p_device_kind: input.deviceKind,
    p_channel: input.channel,
    p_token_sha256: input.tokenSha256,
    p_machine_binding_sha256: input.machineBindingSha256,
  });
}

export async function identifyProductDevice(
  env: ProductPostgresEnv,
  input: {
    tokenSha256: string;
    machineBindingSha256: string;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_identify_product_device_v1", {
    p_token_sha256: input.tokenSha256,
    p_machine_binding_sha256: input.machineBindingSha256,
  });
}

export async function authenticateProductDevice(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    tokenSha256: string;
  },
): Promise<boolean> {
  return callRpc<boolean>(env, "ordax_authenticate_product_device_v1", {
    p_device_id: input.deviceId,
    p_token_sha256: input.tokenSha256,
  });
}

export async function importLegacyProductDevice(
  env: ProductPostgresEnv,
  input: {
    deviceId: string;
    ownerUserId: string;
    displayName: string;
    deviceKind: "desktop" | "laptop" | "mobile" | "server" | "other";
    channel: "stable" | "development";
    tokenSha256: string;
    machineBindingSha256: string;
    lastSeenAt: string | null;
  },
): Promise<JsonObject> {
  return callRpc<JsonObject>(env, "ordax_import_legacy_product_device_v1", {
    p_device_id: input.deviceId,
    p_owner_user_id: input.ownerUserId,
    p_display_name: input.displayName,
    p_device_kind: input.deviceKind,
    p_channel: input.channel,
    p_token_sha256: input.tokenSha256,
    p_machine_binding_sha256: input.machineBindingSha256,
    p_last_seen_at: input.lastSeenAt,
  });
}

/**
 * Canonical grant-group boundary. Not wired into the legacy D1 handlers:
 * changing public endpoints requires a coordinated Product client cutover.
 * PostgreSQL alone enforces access decisions for these RPCs.
 */
export async function replaceRemoteGrantGroup(
  env: ProductPostgresEnv,
  input: RemoteGrantGroupInput,
): Promise<JsonObject> {
  const args = canonicalRemoteGrantGroup(input);
  if (!args) throw new ProductPostgresError("remote_grant_invalid", 400);
  return callRpc<JsonObject>(env, "ordax_replace_remote_grant_group_v1", args);
}

export async function revokeRemoteGrantGroup(
  env: ProductPostgresEnv,
  ownerUserId: string,
  grantGroupId: string,
): Promise<JsonObject> {
  if (!isCanonicalUuid(ownerUserId) || !isCanonicalUuid(grantGroupId)) {
    throw new ProductPostgresError("remote_grant_revoke_invalid", 400);
  }
  return callRpc<JsonObject>(env, "ordax_revoke_remote_grant_group_v1", {
    p_owner_user_id: ownerUserId,
    p_grant_group_id: grantGroupId,
  });
}

export async function listOwnerMcpRemoteAuthority(
  env: ProductPostgresEnv,
  ownerUserId: string,
  deviceId: string,
): Promise<JsonObject> {
  if (!isCanonicalUuid(ownerUserId) || !isCanonicalUuid(deviceId))
    throw new ProductPostgresError("owner_remote_authority_invalid", 400);
  return callRpc<JsonObject>(env, "ordax_owner_mcp_remote_authority_v1", {
    p_owner_user_id: ownerUserId, p_device_id: deviceId,
  });
}

export async function replaceOwnerMcpGrantGroup(
  env: ProductPostgresEnv,
  input: {
    ownerUserId: string; spaceId: string | null; projectId: string | null;
    deviceId: string; clientId: string; profileKey: string;
    capabilities: readonly { capability: string; accessMode: "read" | "write" }[];
    validUntil: string | null;
  },
): Promise<JsonObject> {
  const args = canonicalRemoteGrantGroup({
    ownerUserId: input.ownerUserId, spaceId: input.spaceId, projectId: input.projectId,
    deviceId: input.deviceId, clientKind: "product-mcp", clientId: input.clientId,
    profileKey: input.profileKey, capabilities: [...input.capabilities], validUntil: input.validUntil,
  });
  if (!args) throw new ProductPostgresError("remote_grant_invalid", 400);
  return callRpc<JsonObject>(env, "ordax_replace_owner_mcp_grant_group_v1", {
    p_owner_user_id: args.p_owner_user_id, p_space_id: args.p_space_id,
    p_project_id: args.p_project_id, p_device_id: args.p_device_id,
    p_client_id: args.p_client_id, p_profile_key: args.p_profile_key,
    p_capabilities: args.p_capabilities, p_access_modes: args.p_access_modes,
    p_valid_until: args.p_valid_until,
  });
}

export async function revokeOwnerMcpGrantGroup(
  env: ProductPostgresEnv, ownerUserId: string, clientId: string, grantGroupId: string,
): Promise<JsonObject> {
  if (!isCanonicalUuid(ownerUserId) || !isCanonicalUuid(grantGroupId)
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$/.test(clientId))
    throw new ProductPostgresError("owner_mcp_grant_revoke_invalid", 400);
  return callRpc<JsonObject>(env, "ordax_revoke_owner_mcp_grant_group_v1", {
    p_owner_user_id: ownerUserId, p_client_id: clientId, p_grant_group_id: grantGroupId,
  });
}

export async function listCanonicalProductTargets(
  env: ProductPostgresEnv,
  input: {
    ownerUserId: string;
    clientKind: RemoteClientKind;
    clientId: string | null;
  },
): Promise<JsonObject> {
  const args = canonicalRemoteClient(input.ownerUserId, input.clientKind, input.clientId);
  if (!args) throw new ProductPostgresError("product_target_identity_invalid", 400);
  return callRpc<JsonObject>(env, "ordax_list_product_targets_v1", args);
}


/** Product's only durable Central request-to-ChatGPT conversation mapping.
 * These calls are trusted-server operations, NEVER expose them as model tools.
 * The caller must authenticate the originating Central request and attest the
 * provider session/conversation before binding. Neither a prompt nor a
 * provider _meta marker (which can be forged) alone is authority.
 */
export type CentralSessionRecord = {
  ownerUserId: string;
  clientId: string;
  deviceId: string;
  spaceId: string | null;
  projectId: string | null;
  requestId: string;
  conversationId: string;
  /** Provider correlation marker, kept out of PostgreSQL in raw form. */
  sessionId: string;
};
const CENTRAL_WEB_ID=/^[A-Za-z0-9_-]{8,128}$/;
const CENTRAL_CLIENT_ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$/;
function validCentralRecord(x:CentralSessionRecord): boolean {
  return isCanonicalUuid(x.ownerUserId) && isCanonicalUuid(x.deviceId)
    && isCanonicalUuid(x.requestId)
    && (x.spaceId===null && x.projectId===null
      || (isCanonicalUuid(x.spaceId) && isCanonicalUuid(x.projectId)))
    && CENTRAL_CLIENT_ID.test(x.clientId)
    && CENTRAL_WEB_ID.test(x.conversationId)
    && typeof x.sessionId==="string"
    && x.sessionId.length>=8 && x.sessionId.length<=256
    && !/[\x00-\x20\x7f]/u.test(x.sessionId);
}
async function centralParams(x:CentralSessionRecord):Promise<JsonObject> {
  if(!x || !validCentralRecord(x))
    throw new ProductPostgresError("central_session_invalid",400);
  const hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(x.sessionId));
  const sessionSha256=Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,"0")).join("");
  return {
    p_owner_user_id:x.ownerUserId,
    p_client_id:x.clientId,
    p_device_id:x.deviceId,
    p_space_id:x.spaceId,
    p_project_id:x.projectId,
    p_request_id:x.requestId,
    p_conversation_id:x.conversationId,
    p_session_sha256:sessionSha256,
  };
}
export async function bindProductCentralConversation(
  env:ProductPostgresEnv, trusted:CentralSessionRecord, expiresAt:string,
):Promise<boolean> {
  if(typeof expiresAt!=="string"||Number.isNaN(Date.parse(expiresAt)))
    throw new ProductPostgresError("central_expiry_invalid",400);
  return callRpc<boolean>(env,"ordax_bind_central_conversation_v1",{
    ...await centralParams(trusted),p_expires_at:expiresAt,
  });
}
export async function verifyProductCentralConversation(
  env:ProductPostgresEnv, trusted:CentralSessionRecord,
):Promise<boolean> {
  return callRpc<boolean>(env,"ordax_verify_central_conversation_v1",
    await centralParams(trusted));
}
export async function revokeProductCentralConversation(
  env:ProductPostgresEnv,ownerUserId:string,clientId:string,requestId:string,
):Promise<boolean> {
  if(!isCanonicalUuid(ownerUserId)||!isCanonicalUuid(requestId)
    ||!CENTRAL_CLIENT_ID.test(clientId))
    throw new ProductPostgresError("central_revocation_invalid",400);
  return callRpc<boolean>(env,"ordax_revoke_central_conversation_v1",{
    p_owner_user_id:ownerUserId,p_client_id:clientId,p_request_id:requestId,
  });
}
