export function getCookie(request, name) {
  const cookieHeader =
    request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] =
      cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(
        valueParts.join("=")
      );
    }
  }

  return null;
}

export function setCookie(name, value, options = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`
  ];

  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`);
  }

  if (options.expires) {
    parts.push(
      `Expires=${options.expires.toUTCString()}`
    );
  }

  if (options.path) {
    parts.push(`Path=${options.path}`);
  }

  if (options.domain) {
    parts.push(`Domain=${options.domain}`);
  }

  if (options.secure) {
    parts.push("Secure");
  }

  if (options.httpOnly) {
    parts.push("HttpOnly");
  }

  if (options.sameSite) {
    parts.push(
      `SameSite=${options.sameSite}`
    );
  }

  return parts.join("; ");
}

export function deleteCookie(name, options = {}) {
  return setCookie(name, "", {
    ...options,
    maxAge: 0
  });
}

export function jsonResponse(
  data,
  status = 200,
  headers = {}
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=utf-8",
        ...headers
      }
    }
  );
}

export function jsonError(
  message,
  status = 400
) {
  return jsonResponse(
    {
      error: message
    },
    status
  );
}
