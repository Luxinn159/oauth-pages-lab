import {
  getCookie,
  setCookie
} from "../_shared/cookies.js";

import {
  sha256Hex
} from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const sessionToken = getCookie(
    context.request,
    "__Host-session"
  );

  if (sessionToken) {
    const sessionHash =
      await sha256Hex(sessionToken);

    await context.env.DB.prepare(
      `DELETE FROM sessions
       WHERE id_hash = ?`
    )
      .bind(sessionHash)
      .run();
  }

  const headers = new Headers();

  headers.set("Location", "/");

  headers.append(
    "Set-Cookie",
    setCookie(
      "__Host-session",
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
    status: 303,
    headers
  });
}
