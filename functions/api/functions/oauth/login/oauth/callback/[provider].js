import {
  sha256Hex,
  randomBase64Url
} from "../../_shared/crypto.js";

import {
  getCookie,
  setCookie,
  deleteCookie
} from "../../_shared/cookies.js";

import {
  getProviderConfig
} from "../../_shared/providers.js";

import {
  validateGoogleIdToken
} from "../../_shared/oidc.js";

async function exchangeGoogleCode(
  code,
  transaction,
  config
) {
  const body = new URLSearchParams();

  body.set("client_id", config.clientId);
  body.set("client_secret", config.clientSecret);
  body.set("code", code);
  body.set("code_verifier", transaction.codeVerifier);
  body.set("redirect_uri", config.redirectUri);
  body.set("grant_type", "authorization_code");

  const response = await fetch(
    config.tokenEndpoint,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      body
    }
  );

  if (!response.ok) {
    throw new Error("google_token_exchange_failed");
  }

  const tokens = await response.json();

  if (!tokens.id_token) {
    throw new Error("missing_google_id_token");
  }

  return tokens;
}

async function exchangeGithubCode(
  code,
  transaction,
  config
) {
  const body = new URLSearchParams();

  body.set("client_id", config.clientId);
  body.set("client_secret", config.clientSecret);
  body.set("code", code);
  body.set("redirect_uri", config.redirectUri);
  body.set("code_verifier", transaction.codeVerifier);

  const response = await fetch(
    config.tokenEndpoint,
    {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type":
          "application/x-www-form-urlencoded"
      },
      body
    }
  );

  if (!response.ok) {
    throw new Error("github_token_exchange_failed");
  }

  const tokens = await response.json();

  if (
    !tokens.access_token ||
    String(tokens.token_type).toLowerCase() !== "bearer"
  ) {
    throw new Error("invalid_github_token_response");
  }

  return tokens;
}

async function githubUser(accessToken) {
  const response = await fetch(
    "https://api.github.com/user",
    {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10"
      }
    }
  );

  if (!response.ok) {
    throw new Error("github_user_failed");
  }

  const user = await response.json();

  if (
    !Number.isInteger(user.id)
  ) {
    throw new Error("invalid_github_user");
  }

  return user;
}

async function revokeGithubGrant(
  accessToken,
  config
) {
  const basic = btoa(
    `${config.clientId}:${config.clientSecret}`
  );

  const response = await fetch(
    `https://api.github.com/applications/${encodeURIComponent(
      config.clientId
    )}/grant`,
    {
      method: "DELETE",

      headers: {
        "Authorization": `Basic ${basic}`,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        access_token: accessToken
      })
    }
  );

  if (response.status !== 204) {
    throw new Error("github_revoke_failed");
  }
}

async function createSession(
  context,
  identity
) {
  const session = randomBase64Url(32);

  const idHash =
    await sha256Hex(session);

  const now =
    Math.floor(Date.now() / 1000);

  const expiresAt =
    now + 28800;

  await context.env.DB.prepare(
    `INSERT INTO sessions
     (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      idHash,
      identity.issuer,
      identity.subject,
      identity.email,
      identity.displayName,
      expiresAt,
      now
    )
    .run();

  return session;
}

export async function onRequestGet(context) {
  const provider =
    context.params.provider;

  const config =
    getProviderConfig(
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

  const url =
    new URL(context.request.url);

  const error =
    url.searchParams.get("error");

  const code =
    url.searchParams.get("code");

  const state =
    url.searchParams.get("state");

  if (error || !code || !state) {
    return new Response(
      "OAuth response rejected.",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  const transactionCookie =
    getCookie(
      context.request,
      "__Host-oauth-tx"
    );

  if (!transactionCookie) {
    return new Response(
      "OAuth transaction missing.",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  const transactionHash =
    await sha256Hex(transactionCookie);

  const row =
    await context.env.DB.prepare(
      `SELECT
        id_hash,
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
       FROM oauth_transactions
       WHERE id_hash = ?`
    )
      .bind(transactionHash)
      .first();

  if (!row) {
    return new Response(
      "OAuth transaction not found.",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  const now =
    Math.floor(Date.now() / 1000);

  if (
    row.provider !== provider ||
    row.expires_at <= now
  ) {
    await context.env.DB.prepare(
      "DELETE FROM oauth_transactions WHERE id_hash = ?"
    )
      .bind(transactionHash)
      .run();

    return new Response(
      "OAuth transaction expired.",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  const stateHash =
    await sha256Hex(state);

  if (stateHash !== row.state_hash) {
    await context.env.DB.prepare(
      "DELETE FROM oauth_transactions WHERE id_hash = ?"
    )
      .bind(transactionHash)
      .run();

    return new Response(
      "OAuth state rejected.",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  await context.env.DB.prepare(
    "DELETE FROM oauth_transactions WHERE id_hash = ?"
  )
    .bind(transactionHash)
    .run();

  const transaction = {
    codeVerifier: row.code_verifier,
    nonce: row.nonce
  };

  let identity;

  try {
    if (provider === "google") {
      const tokens =
        await exchangeGoogleCode(
          code,
          transaction,
          config
        );

      const google =
        await validateGoogleIdToken(
          tokens.id_token,
          transaction.nonce,
          config.clientId
        );

      identity = {
        issuer: "https://accounts.google.com",
        subject: google.subject,
        email: google.email,
        displayName: google.displayName
      };
    }

    if (provider === "github") {
      const tokens =
        await exchangeGithubCode(
          code,
          transaction,
          config
        );

      const user =
        await githubUser(
          tokens.access_token
        );

      await revokeGithubGrant(
        tokens.access_token,
        config
      );

      identity = {
        issuer: "https://github.com",
        subject: String(user.id),
        email: user.email ?? null,
        displayName:
          user.name ??
          user.login ??
          null
      };
    }
  } catch (error) {
    return new Response(
      "OAuth identity validation failed.",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  if (!identity) {
    return new Response(
      "Identity unavailable.",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  try {
    const session =
      await createSession(
        context,
        identity
      );

    return new Response(null, {
      status: 302,

      headers: {
        "Location":
          context.env.PUBLIC_BASE_URL,

        "Set-Cookie":
          deleteCookie(
            "__Host-oauth-tx"
          ),

        "Set-Cookie-2":
          setCookie(
            "__Host-session",
            session,
            {
              path: "/",
              httpOnly: true,
              secure: true,
              sameSite: "Strict",
              maxAge: 28800
            }
          ),

        "Cache-Control": "no-store"
      }
    });
  } catch (error) {
    return new Response(
      "Session creation failed.",
      {
        status: 500,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }
}
