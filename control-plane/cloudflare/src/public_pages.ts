export interface PublicPagesEnv {
  OPENAI_APPS_CHALLENGE?: string;
}

const PRODUCT_NAME = "ORDAX";
const REPOSITORY_URL = "https://github.com/washingtonmsdj/ordax-control-plane";
const SUPPORT_URL = "https://github.com/washingtonmsdj/ordax-control-plane/issues";

function html(title: string, body: string): Response {
  const document = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · ${PRODUCT_NAME}</title>
<style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#071019;color:#e9f4ff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(180deg,#071019,#0a1622)}
main{max-width:860px;margin:0 auto;padding:64px 28px 80px}nav{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:48px}
a{color:#9dccff}nav a{text-decoration:none}h1{font-size:42px;letter-spacing:-.03em;margin:0 0 18px}
h2{margin-top:36px;font-size:22px}p,li{color:#b7c8d8;line-height:1.7}code{color:#b9d9ff}
.card{border:1px solid #1d3850;border-radius:18px;background:#0c1b28;padding:22px;margin:22px 0}
.small{font-size:13px;color:#819db3}
</style>
</head>
<body><main>
<nav>
<a href="/">ORDAX</a>
<a href="/support">Support</a>
<a href="/privacy">Privacy</a>
<a href="/terms">Terms</a>
</nav>
${body}
</main></body></html>`;
  return new Response(document, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=300",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

export function publicProductPage(pathname: string): Response | null {
  if (pathname === "/") {
    return html("Home", `
<h1>ORDAX</h1>
<p>ORDAX connects authorized clients to typed capabilities on devices the user controls. The ORDAX Studio ChatGPT connector uses the same grant-scoped Control Plane and device Runtime.</p>
<div class="card">
<strong>What it can do</strong>
<ul>
<li>Work with explicitly registered project files and repositories.</li>
<li>Inspect Git status and run granted Git operations.</li>
<li>Use bounded project commands when the user has granted terminal access.</li>
<li>Use typed Computer Control and specialized adapters when explicitly authorized.</li>
</ul>
</div>
<p>ORDAX does not expose the whole computer by default. Remote actions are limited by device, scope and action grants plus local Runtime policy.</p>
<p><a href="${REPOSITORY_URL}">Source repository and technical documentation</a></p>
<p class="small">ORDAX Control Plane · Cloudflare</p>`);
  }

  if (pathname === "/support") {
    return html("Support", `
<h1>Support</h1>
<p>For ORDAX installation, connection, connector or tool issues, open a support issue in the project repository.</p>
<div class="card">
<p><a href="${SUPPORT_URL}">Open or review support issues</a></p>
<p>Include the affected ORDAX component/version, device or project scope and a concise description of the problem. Do not include passwords, access tokens or private project content.</p>
</div>
<p>Security-sensitive reports should not include exploit details or credentials in a public issue. Use the repository owner's private contact channel when available.</p>`);
  }

  if (pathname === "/privacy") {
    return html("Privacy Policy", `
<h1>Privacy Policy</h1>
<p>Effective: 22 October 2026.</p>
<p>ORDAX is a capability platform that connects an authorized client to devices and scopes the user explicitly connects.</p>
<h2>Data processed</h2>
<ul>
<li><strong>Account and authentication data:</strong> authentication identifiers required to verify the connected ORDAX account. Authentication is currently provided by Supabase Auth; passwords are handled by the identity provider and are not stored by the ORDAX Control Plane.</li>
<li><strong>Device and authorization data:</strong> device identifiers and names, project or Space scopes, grants, allowed actions and connection state needed to route authorized requests.</li>
<li><strong>Requested capability data:</strong> file contents, Git information, Computer Control results, adapter metadata, command results or artifacts only when an authorized tool is invoked for that data.</li>
<li><strong>Operational and audit data:</strong> action names, scope, request/status identifiers, authorization decisions, execution status and timestamps needed for security, reliability and abuse investigation.</li>
<li><strong>MCP usage measurement:</strong> when enabled, the count of successful authenticated tool calls by account, OAuth client, tool and UTC calendar month. A short-lived HMAC-SHA-256 request fingerprint, keyed by a deployment secret, suppresses duplicate transport retries. Tool arguments, prompts and conversation history are not stored by this meter. The meter is currently disabled by default and does not apply subscription quotas or charges.</li>
</ul>
<h2>How data is used</h2>
<p>Data is used to authenticate connections, enforce grants, route tool calls to the selected device, return requested results, maintain reliability and provide security/audit controls. ORDAX does not request the full conversation history of an external AI client.</p>
<h2>Infrastructure</h2>
<p>The remote Control Plane uses Cloudflare services for compute and storage. Account authentication currently uses Supabase Auth. Local project/device data remains on the user's device unless an authorized tool invocation requires selected data or an artifact to transit the Control Plane to fulfill the request.</p>
<h2>Sharing and sale</h2>
<p>ORDAX does not sell personal data. Data is shared with infrastructure providers only as needed to operate the service or when required by law.</p>
<h2>Retention</h2>
<ul>
<li><strong>OAuth credentials:</strong> ORDAX verifies bearer tokens for requests but does not persist the user's OAuth access token in the Control Plane. Authentication records held by the identity provider follow the account lifecycle and the provider's applicable policy.</li>
<li><strong>Temporary Product artifacts:</strong> signed download links expire after 1 hour. Artifact bytes and their Product metadata are retained for no more than 7 days, then the daily retention process deletes both the Cloudflare R2 object and its D1 record.</li>
<li><strong>Product action and audit history:</strong> completed action records, request metadata and audit entries are retained for no more than 30 days for reliability, security and abuse investigation.</li>
<li><strong>MCP usage measurement:</strong> request fingerprints are eligible for deletion after 24 hours and the daily cleanup normally removes them within about 48 hours. Monthly aggregate counts retain only the current and previous UTC calendar month. Cleanup outages may delay deletion.</li>
<li><strong>Device pairings:</strong> pairing secrets expire and expired pairing records are deleted by the next daily retention cycle.</li>
<li><strong>Device links and grants:</strong> active links and grants remain while the user keeps them active. Revoked or expired authorization metadata is retained for no more than 30 days after it becomes inactive, once no retained action history depends on it.</li>
</ul>
<p>These retention periods apply to the ORDAX Product/MCP service. Files that remain only on the user's computer are not copied to the Control Plane unless an authorized tool request needs selected content or an artifact to fulfill that request.</p>
<h2>User control</h2>
<p>Users can stop the local Runtime, revoke device/scope grants, disconnect a provider connector and remove installed software. Access is designed to fail closed when authentication or grants are missing. Retained Product metadata can also be addressed through the <a href="/support">support channel</a>.</p>
<h2>Security</h2>
<p>Device credentials are scoped separately from user authentication. Remote actions are checked against explicit device, scope and action grants plus local policy where applicable. Do not place secrets in prompts or project files unless necessary for the task.</p>
<p>Questions about this policy can be raised through the <a href="/support">support page</a>.</p>`);
  }

  if (pathname === "/terms") {
    return html("Terms of Service", `
<h1>Terms of Service</h1>
<p>Effective: 1 October 2026.</p>
<p>By using ORDAX, you agree to use it only on computers, repositories, accounts and data that you are authorized to access.</p>
<h2>User responsibility</h2>
<p>You are responsible for reviewing requested writes, Git, terminal, Computer Control and specialized adapter actions before authorizing them and for maintaining appropriate backups and version control for important work.</p>
<h2>Service behavior</h2>
<p>ORDAX is provided as evolving software. Availability may change during updates, maintenance or third-party service outages. The service may reject actions that lack a valid grant, exceed safety limits or cannot be verified.</p>
<h2>Prohibited use</h2>
<p>You may not use ORDAX to access systems without authorization, bypass security controls, distribute malicious software, or violate applicable law or third-party rights.</p>
<h2>Third-party services</h2>
<p>ORDAX relies on third-party infrastructure including Cloudflare and the configured identity provider. Provider-specific connectors can also be subject to the terms of their respective providers.</p>
<h2>Changes</h2>
<p>Material changes to these terms will be reflected on this page with an updated effective date.</p>
<p>Questions can be raised through the <a href="/support">support page</a>.</p>`);
  }

  return null;
}

export function openAiAppsChallenge(env: PublicPagesEnv): Response {
  const token = (env.OPENAI_APPS_CHALLENGE ?? "").trim();
  if (!token || token.length > 4096 || /[\r\n]/.test(token)) {
    return new Response("not configured", {
      status: 404,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
    });
  }
  return new Response(token, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
