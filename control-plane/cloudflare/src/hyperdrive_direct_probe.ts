/** Diagnostic Worker, never a Product MCP authority. No D1/OAuth/owner state.
 * Uses the Hyperdrive binding of ONE ephemeral configuration and SELECT 1.
 */
import { connect } from "cloudflare:sockets";
import {
  openPostgresSession,
  type DatabaseTlsTrust,
} from "./data_postgres_driver.ts";

type Env = {
  POSTGRES?: { connectionString: string };
  ORDAX_PROBE_ORIGIN_HOST: string;
  ORDAX_PROBE_ORIGIN_PORT: string;
  ORDAX_PROBE_DIRECT_POSTGRES?: string;
  ORDAX_PROBE_DB_USER?: string;
  ORDAX_PROBE_DB_PASSWORD?: string;
  ORDAX_PROBE_TLS_CA?: string;
};

// Public Supabase 2021 trust chain observed from the project endpoint.
// This is certificate authority material, never a credential.
const SUPABASE_2021_CA_CHAIN = `-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIUBhalAwMQ7BA1NH7td4msPPwxHzowDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l
dyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJh
c2UgUm9vdCAyMDIxIENBMB4XDTIzMTAyNDA3NTM0NVoXDTMzMTAyMTA3NTM0NVow
czELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5ldyBD
YXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEmMCQGA1UEAwwdU3VwYWJhc2Ug
SW50ZXJtZWRpYXRlIDIwMjEgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDOAMhXirH+EGIn8GaDp8T53rEogf7kM8OKW2uQ5yU/wxPa+w8BXgTzWy3W
JDAUhZE78oUtAd9kk5zKPrLXoT3W61PPnOc/9dceL5gB7/78m7EKCySziAA2c8vR
fnYPfznedDXi2lryttSYmMf2qbZDErAxwJDUm6cyq+HLAfb2qUH28u6jP8I9GDtG
PkQnjqtiRXEKjbTc/ntqCQrhtFK02mHkMSju7nEpkNYryunv5n/c9mrRY9/8GwmP
3uSZz3CQ8yQ/E0f8T9gCca2TcKuTQmW2pQqtHv1MuZ3jfJE5Nr9+Fap5kdzDJtdf
BdKofVNZlnYIru5yhUZywY3xYFfHAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8w
DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQVoFMuvXJ9Yv+QJr6/GJX0Z0VA+jAf
BgNVHSMEGDAWgBSo17l2N9gs7ZISJp4OMiTVLWlGLDANBgkqhkiG9w0BAQsFAAOC
AQEAcjxkXf4FIEbJEBmMAuh313ua6btovY0apR+gP8NfLZmjUh0q9Oc7TmMVRtuW
JIL9jlEMqw0Y4PP3+//pSvMiaxqaGhmXsgrd3w1B5vQnaASuerra3UhFX9CJnpMd
jGxaXipY8zJa602lEwzD24wrKriRRqOhX2NRLHeQuTkQiQgFTnDx1pJhqZ78hnKX
ccaawiv1PA2Tl253LdQaYv6VcJ5mh1jobznRBkfHen2kDgt17YKJW3ttLzaCMiLu
5iqgXEf0E58pLZE5e2jutI7oEHFH7KTAPG5Xguoyond/HSq4bTK31lVva3S7Du87
cCQq7WEcSzy2kH6DWMkWoF0zbg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDxDCCAqygAwIBAgIUbLxMod62P2ktCiAkxnKJwtE9VPYwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l
dyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJh
c2UgUm9vdCAyMDIxIENBMB4XDTIxMDQyODEwNTY1M1oXDTMxMDQyNjEwNTY1M1ow
azELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5ldyBD
YXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJhc2Ug
Um9vdCAyMDIxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQXW
QyHOB+qR2GJobCq/CBmQ40G0oDmCC3mzVnn8sv4XNeWtE5XcEL0uVih7Jo4Dkx1Q
DmGHBH1zDfgs2qXiLb6xpw/CKQPypZW1JssOTMIfQppNQ87K75Ya0p25Y3ePS2t2
GtvHxNjUV6kjOZjEn2yWEcBdpOVCUYBVFBNMB4YBHkNRDa/+S4uywAoaTWnCJLUi
cvTlHmMw6xSQQn1UfRQHk50DMCEJ7Cy1RxrZJrkXXRP3LqQL2ijJ6F4yMfh+Gyb4
O4XajoVj/+R4GwywKYrrS8PrSNtwxr5StlQO8zIQUSMiq26wM8mgELFlS/32Uclt
NaQ1xBRizkzpZct9DwIDAQABo2AwXjALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFKjX
uXY32CztkhImng4yJNUtaUYsMB8GA1UdIwQYMBaAFKjXuXY32CztkhImng4yJNUt
aUYsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB8spzNn+4VU
tVxbdMaX+39Z50sc7uATmus16jmmHjhIHz+l/9GlJ5KqAMOx26mPZgfzG7oneL2b
VW+WgYUkTT3XEPFWnTp2RJwQao8/tYPXWEJDc0WVQHrpmnWOFKU/d3MqBgBm5y+6
jB81TU/RG2rVerPDWP+1MMcNNy0491CTL5XQZ7JfDJJ9CCmXSdtTl4uUQnSuv/Qx
Cea13BX2ZgJc7Au30vihLhub52De4P/4gonKsNHYdbWjg7OWKwNv/zitGDVDB9Y2
CMTyZKG3XEu5Ghl1LEnI3QmEKsqaCLv12BnVjbkSeZsMnevJPs1Ye6TjjJwdik5P
o/bKiIz+Fq8=
-----END CERTIFICATE-----
`;

function safeError(error: unknown): string {
  const record = error && typeof error === "object"
    ? error as Record<string, unknown> : {};
  const cause = record.cause && typeof record.cause === "object"
    ? record.cause as Record<string, unknown> : {};
  const code = String(record.code ?? "").toUpperCase();
  const providerCode = String(cause.code ?? "").toUpperCase();
  const msg = [record.message, record.detail, cause.message, cause.detail]
    .filter((value): value is string => typeof value === "string")
    .map(value => value.toLowerCase()).join(" ");

  // A SQLSTATE 58000 is Hyperdrive's envelope for provider-specific runtime
  // failures. Inspect only allowlisted categories BEFORE returning the generic
  // SQLSTATE so the diagnostic can distinguish a provider failure without
  // reflecting any message, hostname, connection string or credential.
  if (msg.includes("failed to acquire a connection from the pool")) {
    return "hyperdrive_pool_acquire_failed";
  }
  if (msg.includes("server connection attempt failed")) {
    return "hyperdrive_server_connection_failed";
  }
  if (msg.includes("server return error and closed connection")) {
    return "hyperdrive_server_closed_connection";
  }
  if (msg.includes("failed to connect to the provided database")) {
    return "hyperdrive_database_connect_failed";
  }
  if (msg.includes("internal error")) return "hyperdrive_internal_error";
  if (msg.includes("generic error")) return "hyperdrive_generic_error";
  if (msg.includes("connection terminated unexpectedly")) return "connection_terminated";
  if (msg.includes("authentication") || msg.includes("password")) return "authentication_failed";
  if (msg.includes("tls") || msg.includes("certificate")) return "tls_failure";
  if (msg.includes("timeout")) return "timeout";
  if (msg.includes("network") || msg.includes("connection")) return "connection_failed";

  // Cloudflare documents provider connection codes 2008..2016. Expose only
  // that finite allowlist if a wrapped cause carries one.
  if (/^20(?:08|09|10|11|12|13|14|15|16)$/.test(providerCode)) {
    return "hyperdrive_code_" + providerCode;
  }

  // SQLSTATE is a five-character public protocol identifier. Returning only
  // this bounded code reveals the error class without arbitrary provider data.
  if (/^[0-9A-Z]{5}$/.test(code)) return "sqlstate_" + code;
  return "unclassified";
}

function probeConnectionString(env: Env): string | null {
  if (env.ORDAX_PROBE_DIRECT_POSTGRES === "1") {
    const user = (env.ORDAX_PROBE_DB_USER ?? "").trim();
    const password = env.ORDAX_PROBE_DB_PASSWORD ?? "";
    const host = (env.ORDAX_PROBE_ORIGIN_HOST ?? "").trim();
    const port = Number(env.ORDAX_PROBE_ORIGIN_PORT);
    if (!user || !password || !host || !Number.isInteger(port)
        || port < 1 || port > 65535) return null;
    const sslMode = env.ORDAX_PROBE_TLS_CA === "1" ? "" : "?sslmode=require";
    const authorityHost = host.includes(":") ? `[${host}]` : host;
    return `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}`
      + `@${authorityHost}:${port}/postgres${sslMode}`;
  }
  const connectionString = (env.POSTGRES?.connectionString ?? "").trim();
  return connectionString || null;
}

function probeTlsTrust(env: Env): DatabaseTlsTrust | undefined {
  if (env.ORDAX_PROBE_TLS_CA !== "1") return undefined;
  const servername = (env.ORDAX_PROBE_ORIGIN_HOST ?? "").trim();
  if (!servername) return undefined;
  return {
    ca: SUPABASE_2021_CA_CHAIN,
    rejectUnauthorized: true,
    servername,
  };
}

async function probeOriginTcp(env: Env): Promise<boolean> {
  const port = Number(env.ORDAX_PROBE_ORIGIN_PORT);
  if (!env.ORDAX_PROBE_ORIGIN_HOST || !Number.isInteger(port)
      || port < 1 || port > 65535) return false;
  const socket = connect(
    { hostname: env.ORDAX_PROBE_ORIGIN_HOST, port },
    { secureTransport: "off", allowHalfOpen: false },
  );
  try {
    await Promise.race([
      socket.opened,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("tcp_probe_timeout")), 5000)),
    ]);
    return true;
  } catch {
    return false;
  } finally {
    await socket.close().catch(() => {});
  }
}

async function probePostgresTls(env: Env): Promise<
  "ok" | "ssl_request_rejected" | "tls_upgrade_failed"
> {
  const port = Number(env.ORDAX_PROBE_ORIGIN_PORT);
  const hostname = (env.ORDAX_PROBE_ORIGIN_HOST ?? "").trim();
  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    return "tls_upgrade_failed";
  }

  const socket = connect(
    { hostname, port },
    { secureTransport: "starttls", allowHalfOpen: false },
  );
  let secureSocket: ReturnType<typeof connect> | null = null;
  try {
    await Promise.race([
      socket.opened,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("tls_probe_open_timeout")), 5000)),
    ]);

    // PostgreSQL SSLRequest: length=8, code=80877103 (0x04D2162F).
    const writer = socket.writable.getWriter();
    await writer.write(new Uint8Array([0, 0, 0, 8, 4, 210, 22, 47]));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    const reply = await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("ssl_request_timeout")), 5000)),
    ]);
    reader.releaseLock();
    if (reply.done || !reply.value?.byteLength || reply.value[0] !== 83) {
      return "ssl_request_rejected";
    }

    secureSocket = socket.startTls();
    await Promise.race([
      secureSocket.opened,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("tls_upgrade_timeout")), 5000)),
    ]);
    return "ok";
  } catch {
    return "tls_upgrade_failed";
  } finally {
    if (secureSocket) {
      await secureSocket.close().catch(() => {});
    } else {
      await socket.close().catch(() => {});
    }
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "GET" || new URL(request.url).pathname !== "/") {
      return new Response("Not found", { status: 404 });
    }
    // Raw Worker TCP egress and Hyperdrive egress are different networks.
    // Never use a Worker-socket preflight to decide whether Hyperdrive can reach
    // the database. It is authoritative only for direct-Postgres probe modes.
    if (env.ORDAX_PROBE_DIRECT_POSTGRES === "1") {
      const tcpReachable = await probeOriginTcp(env);
      if (!tcpReachable) {
        return Response.json(
          { ok: false, phase: "tcp", classification: "origin_tcp_unreachable" },
          { status: 503 },
        );
      }
      const tls = await probePostgresTls(env);
      if (tls !== "ok") {
        return Response.json(
          { ok: false, phase: "tls", classification: tls },
          { status: 503 },
        );
      }
    }
    const connectionString = probeConnectionString(env);
    if (!connectionString) {
      return Response.json(
        { ok: false, phase: "connect", classification: "probe_connection_unconfigured" },
        { status: 503 },
      );
    }
    const client = openPostgresSession(connectionString, probeTlsTrust(env));
    let phase = "connect";
    try {
      await client.connect();
      phase = "query";
      const result = await client.query("select 1::int as ok");
      const ok = result.rows?.[0]?.ok === 1;
      return Response.json({ ok, phase: "complete" }, { status: ok ? 200 : 503 });
    } catch (error) {
      return Response.json({ ok: false, phase, classification: safeError(error) },
                           { status: 503 });
    } finally {
      await client.end().catch(() => {});
    }
  },
};
