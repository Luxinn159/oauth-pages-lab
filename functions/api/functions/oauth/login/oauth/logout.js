import {
  getCookie,
  deleteCookie
} from "../_shared/cookies.js";

import {
  sha256Hex
} from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const origin =
    context.request.headers.get("Origin");

  if (
    origin !==
    context.env.PUBLIC_BASE_URL
  ) {
    return new Response(
      "Invalid origin.",
      {
        status: 403,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  const cookie =
    getCookie(
      context.request,
      "__Host-session"
    );

  if (cookie) {
    const idHash =
      await sha256Hex(cookie);

    await context.env.DB.prepare(
      "DELETE FROM sessions WHERE id_hash = ?"
    )
      .bind(idHash)
      .run();
  }

  const headers = new Headers();

  headers.append(
    "Set-Cookie",
    deleteCookie("__Host-session")
  );

  headers.set(
    "Cache-Control",
    "no-store"
  );

  headers.set(
    "Location",
    context.env.PUBLIC_BASE_URL
  );

  return new Response(null, {
    status: 303,
    headers
  });
}
