import {
  sha256Hex
} from "../../_shared/crypto.js";

import {
  getCookie,
  setCookie,
  jsonError
} from "../../_shared/cookies.js";

import {
  getProviderConfig
} from "../../_shared/providers.js";

import {
  validateGoogleIdToken
} from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;
  const url = new URL(context.request.url);

  const config = getProviderConfig(
    provider,
    context.env
  );

  if (!config) {
    return jsonError("unsupported_provider", 404);
  }

  const error = url.searchParams.get("error");

  if (error) {
    return jsonError(error, 400);
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return jsonError("missing_code_or_state", 400);
  }

  const transaction =
    getCookie(
      context.request,
      "__Host-oauth-tx"
    );

  if (!transaction) {
    return jsonError(
      "missing_oauth_transaction",
      400
    );
  }

  const transactionHash =
    await sha256Hex(transaction);

  const stateHash =
    await sha256Hex(state);

  const transactionRow =
    await context.env.DB.prepare(
      `SELECT
        id_hash,
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
       FROM oauth_transactions
       WHERE id_hash = ?
       AND expires_at > ?`
    )
      .bind(
        transactionHash,
        Math.floor(Date.now() / 1000)
      )
      .first();

  if (!transactionRow) {
    return jsonError(
      "invalid_or_expired_transaction",
      400
    );
  }

  if (transactionRow.provider !== provider) {
    return jsonError(
      "provider_mismatch",
      400
    );
  }

  if (transactionRow.state_hash !== stateHash) {
    return jsonError(
      "invalid_state",
      400
    );
  }

  const tokenBody = new URLSearchParams();

  tokenBody.set(
    "grant_type",
    "authorization_code"
  );

  tokenBody.set(
    "code",
    code
  );

  tokenBody.set(
    "client_id",
    config.clientId
  );

  tokenBody.set(
    "redirect_uri",
    config.redirectUri
  );

  tokenBody.set(
    "code_verifier",
    transactionRow.code_verifier
  );

  if (config.clientSecret) {
    tokenBody.set(
      "client_secret",
      config.clientSecret
    );
  }

  const tokenResponse = await fetch(
    config.tokenEndpoint,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
        "Accept":
          "application/json"
      },
      body: tokenBody.toString()
    }
  );

  if (!tokenResponse.ok) {
    return jsonError(
      "token_exchange_failed",
      502
    );
  }

  const tokenData =
    await tokenResponse.json();

  if (!tokenData.access_token) {
    return jsonError(
      "missing_access_token",
      502
    );
  }

  let subject = null;
  let email = null;
  let displayName = null;
  let issuer = config.issuer || provider;

  if (provider === "google") {
    try {
      const identity =
        await validateGoogleIdToken(
          tokenData.id_token,
          transactionRow.nonce,
          config.clientId
        );

      subject = identity.subject;
      email = identity.email;
      displayName = identity.displayName;
    } catch {
      return jsonError(
        "invalid_google_identity",
        401
      );
    }
  }

  if (provider === "github") {
    const userResponse = await fetch(
      config.userEndpoint,
      {
        headers: {
          "Authorization":
            `Bearer ${tokenData.access_token}`,
          "Accept":
            "application/vnd.github+json",
          "User-Agent":
            "oauth-pages-lab"
        }
      }
    );

    if (!userResponse.ok) {
      return jsonError(
        "github_userinfo_failed",
        502
      );
    }

    const user =
      await userResponse.json();

    if (!user.id) {
      return jsonError(
        "invalid_github_identity",
        401
      );
    }

    subject = String(user.id);
    email = user.email || null;
    displayName =
      user.name ||
      user.login ||
      null;

    issuer = "https://github.com";
  }

  if (!subject) {
    return jsonError(
      "missing_subject",
      401
    );
  }

  const sessionToken =
    crypto.randomUUID() +
    crypto.randomUUID();

  const sessionHash =
    await sha256Hex(sessionToken);

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    60 * 60 * 24 * 7;

  await context.env.DB.prepare(
    `INSERT INTO sessions
     (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      sessionHash,
      issuer,
      subject,
      email,
      displayName,
      expiresAt,
      Math.floor(Date.now() / 1000)
    )
    .run();

  await context.env.DB.prepare(
    `DELETE FROM oauth_transactions
     WHERE id_hash = ?`
  )
    .bind(transactionHash)
    .run();

  const headers = new Headers();

  headers.set(
    "Location",
    "/"
  );

  headers.append(
    "Set-Cookie",
    setCookie(
      "__Host-session",
      sessionToken,
      {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        maxAge: 60 * 60 * 24 * 7
      }
    )
  );

  headers.append(
    "Set-Cookie",
    setCookie(
      "__Host-oauth-tx",
      "",
      {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        maxAge: 0
      }
    )
  );

  headers.set(
    "Cache-Control",
    "no-store"
  );

  return new Response(null, {
    status: 302,
    headers
  });
}
// force redeploy created_at fix
