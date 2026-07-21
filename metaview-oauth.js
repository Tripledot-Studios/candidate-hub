/**
 * metaview-oauth.js
 *
 * Shared by index.html (the hub builder) and metaview-callback.html.
 * Implements a standards-based MCP OAuth client:
 *   1. Discover the authorization server via RFC 9728 / RFC 8414 metadata
 *   2. Register this app as an OAuth client via Dynamic Client Registration (RFC 7591),
 *      if the server supports it — falls back to a manually-configured client ID otherwise
 *   3. Run the Authorization Code + PKCE flow (RFC 7636) in a popup window
 *   4. Store the resulting per-recruiter access/refresh token in *that recruiter's own browser*
 *      (localStorage) — nothing is shared across recruiters or devices.
 *
 * Each recruiter's browser does its own one-time "connect" — this is expected MCP behavior,
 * not a bug (each browser is its own OAuth client installation).
 */

const MV_MCP_URL = 'https://mcp.metaview.ai/mcp';
const MV_REDIRECT_URI = 'https://tripledot-studios.github.io/candidate-hub/metaview-callback.html';

// If Metaview's server does NOT support Dynamic Client Registration, set a manually-issued
// client ID here (ask Metaview for one, tied to MV_REDIRECT_URI above) and DCR will be skipped.
const MV_MANUAL_CLIENT_ID = ''; // leave blank to attempt automatic DCR

const MV_KEYS = {
  clientId: 'mv_oauth_client_id',
  accessToken: 'mv_oauth_access_token',
  refreshToken: 'mv_oauth_refresh_token',
  expiresAt: 'mv_oauth_expires_at',
  authServerConfig: 'mv_oauth_server_config',
};

// ── Discovery ──────────────────────────────────────────────────────────────

async function mvDiscoverConfig() {
  const cached = localStorage.getItem(MV_KEYS.authServerConfig);
  if (cached) {
    try { return JSON.parse(cached); } catch { /* fall through and re-discover */ }
  }

  // RFC 9728: ask the MCP server itself where its authorization server is
  const mcpUrl = new URL(MV_MCP_URL);
  const prmUrl = `${mcpUrl.origin}/.well-known/oauth-protected-resource${mcpUrl.pathname}`;
  let authServerUrl = mcpUrl.origin; // fallback: assume same origin

  try {
    const prmRes = await fetch(prmUrl);
    if (prmRes.ok) {
      const prm = await prmRes.json();
      if (prm.authorization_servers?.[0]) authServerUrl = prm.authorization_servers[0];
    }
  } catch { /* fall back to same-origin guess below */ }

  // RFC 8414: fetch the authorization server's own metadata
  const asMetaUrl = `${new URL(authServerUrl).origin}/.well-known/oauth-authorization-server`;
  const asRes = await fetch(asMetaUrl);
  if (!asRes.ok) throw new Error(`Could not discover Metaview's OAuth configuration (HTTP ${asRes.status} from ${asMetaUrl})`);
  const config = await asRes.json();

  localStorage.setItem(MV_KEYS.authServerConfig, JSON.stringify(config));
  return config;
}

// ── Dynamic Client Registration ─────────────────────────────────────────────

async function mvEnsureClientId(config) {
  if (MV_MANUAL_CLIENT_ID) return MV_MANUAL_CLIENT_ID;

  const cached = localStorage.getItem(MV_KEYS.clientId);
  if (cached) return cached;

  if (!config.registration_endpoint) {
    throw new Error('Metaview\'s OAuth server does not support automatic registration (DCR) and no manual client ID is configured. Ask Metaview for a client_id and set MV_MANUAL_CLIENT_ID in metaview-oauth.js.');
  }

  const res = await fetch(config.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Tripledot Candidate Hub',
      redirect_uris: [MV_REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none', // public client — PKCE only, no secret
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Client registration failed (HTTP ${res.status}): ${body.slice(0, 200)}`);
  }
  const data = await res.json();
  localStorage.setItem(MV_KEYS.clientId, data.client_id);
  return data.client_id;
}

// ── PKCE helpers ─────────────────────────────────────────────────────────

function mvBase64UrlEncode(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function mvGenerateCodeVerifier() {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  return mvBase64UrlEncode(bytes);
}

async function mvGenerateCodeChallenge(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return mvBase64UrlEncode(new Uint8Array(digest));
}

// ── Connect flow (call this from a "Connect Metaview" button) ─────────────

async function mvConnect() {
  const config = await mvDiscoverConfig();
  const clientId = await mvEnsureClientId(config);

  const verifier = mvGenerateCodeVerifier();
  const challenge = await mvGenerateCodeChallenge(verifier);
  const state = mvBase64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));

  sessionStorage.setItem('mv_pkce_verifier', verifier);
  sessionStorage.setItem('mv_pkce_state', state);

  const authUrl = new URL(config.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', MV_REDIRECT_URI);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);

  return new Promise((resolve, reject) => {
    const popup = window.open(authUrl.toString(), 'metaview-connect', 'width=520,height=680');
    if (!popup) { reject(new Error('Popup blocked — please allow popups for this site and try again.')); return; }

    const timer = setInterval(() => {
      if (popup.closed) {
        clearInterval(timer);
        window.removeEventListener('message', onMessage);
        reject(new Error('Connection window was closed before finishing.'));
      }
    }, 500);

    function onMessage(event) {
      if (event.origin !== window.location.origin) return;
      if (!event.data || event.data.source !== 'metaview-oauth-callback') return;

      clearInterval(timer);
      window.removeEventListener('message', onMessage);
      popup.close();

      const { code, state: returnedState, error } = event.data;
      if (error) { reject(new Error(`Metaview login failed: ${error}`)); return; }

      const expectedState = sessionStorage.getItem('mv_pkce_state');
      if (returnedState !== expectedState) { reject(new Error('OAuth state mismatch — possible interference, please try again.')); return; }

      mvExchangeCode(config, clientId, code, sessionStorage.getItem('mv_pkce_verifier'))
        .then(resolve)
        .catch(reject);
    }
    window.addEventListener('message', onMessage);
  });
}

async function mvExchangeCode(config, clientId, code, verifier) {
  const res = await fetch(config.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: MV_REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Token exchange failed (HTTP ${res.status}): ${body.slice(0, 200)}`);
  }
  const data = await res.json();
  mvStoreTokens(data);
  return data;
}

function mvStoreTokens(data) {
  localStorage.setItem(MV_KEYS.accessToken, data.access_token);
  if (data.refresh_token) localStorage.setItem(MV_KEYS.refreshToken, data.refresh_token);
  const expiresAt = Date.now() + (data.expires_in ? data.expires_in * 1000 : 55 * 60 * 1000);
  localStorage.setItem(MV_KEYS.expiresAt, String(expiresAt));
}

// ── Using the stored token ─────────────────────────────────────────────────

function mvIsConnected() {
  return !!localStorage.getItem(MV_KEYS.accessToken);
}

async function mvGetValidToken() {
  const token = localStorage.getItem(MV_KEYS.accessToken);
  if (!token) return null;

  const expiresAt = Number(localStorage.getItem(MV_KEYS.expiresAt) || 0);
  if (Date.now() < expiresAt - 60000) return token; // still valid, with 1 min buffer

  const refreshToken = localStorage.getItem(MV_KEYS.refreshToken);
  if (!refreshToken) return token; // no refresh available — try the (possibly expired) token anyway

  try {
    const config = await mvDiscoverConfig();
    const clientId = await mvEnsureClientId(config);
    const res = await fetch(config.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId }),
    });
    if (!res.ok) return token; // refresh failed — fall back to old token, let the caller handle a 401
    const data = await res.json();
    mvStoreTokens(data);
    return data.access_token;
  } catch {
    return token;
  }
}

function mvDisconnect() {
  Object.values(MV_KEYS).forEach(k => { if (k !== MV_KEYS.authServerConfig) localStorage.removeItem(k); });
}
