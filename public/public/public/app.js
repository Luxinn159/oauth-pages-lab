fetch(
  "/api/me",
  {
    credentials: "same-origin"
  }
)
  .then(
    (response) =>
      response.ok
        ? response.json()
        : null
  )
  .then(
    (user) => {
      const status =
        document.getElementById(
          "status"
        );

      const login =
        document.getElementById(
          "login"
        );

      const logout =
        document.getElementById(
          "logout"
        );

      if (user) {
        status.textContent =
          `Sessão de ${
            user.email ??
            user.displayName ??
            "usuário"
          }.`;

        login.hidden = true;
        logout.hidden = false;
      } else {
        status.textContent =
          "Nenhuma sessão neste navegador.";

        login.hidden = false;
        logout.hidden = true;
      }
    }
  )
  .catch(
    () => {
      document.getElementById(
        "status"
      ).textContent =
        "Não foi possível consultar a sessão.";
    }
  );
