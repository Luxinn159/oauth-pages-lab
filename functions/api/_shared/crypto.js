function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function randomBase64Url(length = 32) {
  return bytesToBase64Url(randomBytes(length));
}

export async function sha256(value) {
  const data = new TextEncoder().encode(value);

  const hash = await crypto.subtle.digest("SHA-256", data);

  return new Uint8Array(hash);
}

export async function sha256Hex(value) {
  const hash = await sha256(value);

  return Array.from(hash)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Base64Url(value) {
  const hash = await sha256(value);

  return bytesToBase64Url(hash);
}
