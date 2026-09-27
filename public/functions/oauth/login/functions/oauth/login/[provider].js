import {
  randomBase64Url,
  sha256Base64Url,
  sha256Hex
} from "../../_shared/crypto.js";

import {
  setCookie,
  jsonError
} from "../../_shared/cookies.js";

import {
  getProviderConfig
} from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;

  const config = getProviderConfig(
    provider,
    context.env
  );

  if (!config) {
    return new Response("Not Found", {
      status: 404,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  const transaction = randomBase64Url(32);
  const state = randomBase64Url(32);
  const codeVerifier = randomBase64Url(32);

  const nonce =
    provider === "google"
      ? randomBase64Url(32)
      : null;

  const transactionHash =
    await sha256Hex(transaction);

  const stateHash =
    await sha256Hex(state);

  const codeChallenge =
    await sha256Base64Url(codeVerifier);

  const expiresAt =
    Math.floor(Date.now() / 1000) + 600;

  await context.env.DB.prepare(
    `INSERT INTO oauth_transactions
     (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(
      transactionHash,
      provider,
      stateHash,
      nonce,
      codeVerifier,
      expiresAt
    )
    .run();

  const authorizationUrl =
    new URL(config.authorizationEndpoint);

  authorizationUrl.searchParams.set(
    "client_id",
    config.clientId
  );

  authorizationUrl.searchParams.set(
    "redirect_uri",
    config.redirectUri
  );

  authorizationUrl.searchParams.set(
    "response_type",
    "code"
  );

  authorizationUrl.searchParams.set(
    "state",
    state
  );

  authorizationUrl.searchParams.set(
    "code_challenge",
    codeChallenge
  );

  authorizationUrl.searchParams.set(
    "code_challenge_method",
    "S256"
  );

  if (provider === "google") {
    authorizationUrl.searchParams.set(
      "scope",
      "openid email profile"
    );

    authorizationUrl.searchParams.set(
      "nonce",
      nonce
    );
  }

  return new Response(null, {
    status: 302,

    headers: {
      "Location": authorizationUrl.toString(),

      "Set-Cookie": setCookie(
        "__Host-oauth-tx",
        transaction,
        {
          path: "/",
          httpOnly: true,
          secure: true,
          sameSite: "Lax",
          maxAge: 600
        }
      ),

      "Cache-Control": "no-store"
    }
  });
}
