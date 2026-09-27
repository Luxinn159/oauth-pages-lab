import {
  getCookie
} from "../_shared/cookies.js";

import {
  sha256Hex
} from "../_shared/crypto.js";

export async function onRequestGet(context) {
  const cookie =
    getCookie(
      context.request,
      "__Host-session"
    );

  if (!cookie) {
    return new Response(null, {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  const idHash =
    await sha256Hex(cookie);

  const now =
    Math.floor(Date.now() / 1000);

  const session =
    await context.env.DB.prepare(
      `SELECT
        issuer,
        subject,
        email,
        display_name,
        expires_at
       FROM sessions
       WHERE id_hash = ?
       AND expires_at > ?`
    )
      .bind(idHash, now)
      .first();

  if (!session) {
    return new Response(null, {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  return Response.json(
    {
      email: session.email,
      displayName: session.display_name
    },
    {
      status: 200,
      headers: {
        "Cache-Control": "no-store"
      }
    }
  );
}
