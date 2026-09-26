function decodeBase64Url(value) {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");

  const binary = atob(padded);

  const bytes = Uint8Array.from(
    binary,
    (char) => char.charCodeAt(0)
  );

  return new TextDecoder().decode(bytes);
}

function parseJwtPart(value) {
  return JSON.parse(decodeBase64Url(value));
}

export async function validateGoogleIdToken(
  idToken,
  expectedNonce,
  clientId
) {
  if (typeof idToken !== "string") {
    throw new Error("missing_id_token");
  }

  const parts = idToken.split(".");

  if (parts.length !== 3) {
    throw new Error("invalid_jwt");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const header = parseJwtPart(encodedHeader);
  const payload = parseJwtPart(encodedPayload);

  if (header.alg !== "RS256") {
    throw new Error("invalid_algorithm");
  }

  if (!header.kid) {
    throw new Error("missing_kid");
  }

  const discoveryResponse = await fetch(
    "https://accounts.google.com/.well-known/openid-configuration"
  );

  if (!discoveryResponse.ok) {
    throw new Error("oidc_discovery_failed");
  }

  const discovery = await discoveryResponse.json();

  if (discovery.issuer !== "https://accounts.google.com") {
    throw new Error("invalid_issuer_configuration");
  }

  const jwksResponse = await fetch(discovery.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error("jwks_failed");
  }

  const jwks = await jwksResponse.json();

  const jwk = jwks.keys.find(
    (key) => key.kid === header.kid
  );

  if (!jwk) {
    throw new Error("unknown_signing_key");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const data = new TextEncoder().encode(
    `${encodedHeader}.${encodedPayload}`
  );

  const signatureBinary = atob(
    encodedSignature
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(
        Math.ceil(encodedSignature.length / 4) * 4,
        "="
      )
  );

  const signature = Uint8Array.from(
    signatureBinary,
    (char) => char.charCodeAt(0)
  );

  const validSignature = await crypto.subtle.verify(
    {
      name: "RSASSA-PKCS1-v1_5"
    },
    publicKey,
    signature,
    data
  );

  if (!validSignature) {
    throw new Error("invalid_signature");
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== "https://accounts.google.com") {
    throw new Error("invalid_issuer");
  }

  if (payload.aud !== clientId) {
    throw new Error("invalid_audience");
  }

  if (
    typeof payload.exp !== "number" ||
    payload.exp <= now
  ) {
    throw new Error("expired_token");
  }

  if (
    typeof payload.iat !== "number" ||
    payload.iat > now + 300
  ) {
    throw new Error("invalid_iat");
  }

  if (payload.nonce !== expectedNonce) {
    throw new Error("invalid_nonce");
  }

  if (!payload.sub) {
    throw new Error("missing_subject");
  }

  return {
    subject: String(payload.sub),
    email: payload.email ?? null,
    displayName: payload.name ?? null
  };
}
