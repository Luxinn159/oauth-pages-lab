export function getProviderConfig(provider, env) {
  const base = env.PUBLIC_BASE_URL;

  if (provider === "google") {
    return {
      name: "google",
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,

      authorizationEndpoint:
        "https://accounts.google.com/o/oauth2/v2/auth",

      tokenEndpoint:
        "https://oauth2.googleapis.com/token",

      redirectUri:
        `${base}/oauth/callback/google`,

      scope:
        "openid email profile",

      issuer:
        "https://accounts.google.com"
    };
  }

  if (provider === "github") {
    return {
      name: "github",
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,

      authorizationEndpoint:
        "https://github.com/login/oauth/authorize",

      tokenEndpoint:
        "https://github.com/login/oauth/access_token",

      redirectUri:
        `${base}/oauth/callback/github`,

      userEndpoint:
        "https://api.github.com/user"
    };
  }

  return null;
}
