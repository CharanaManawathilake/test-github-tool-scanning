# test-github-tool-scanning

A sandbox repo for seeing how GitHub's **Security → Code scanning** tab presents
results from static analysis tools.

> ⚠️ `vulnerable_app/` is **intentionally insecure**. Never deploy or run it on a
> reachable network.

## What's inside

| Path | Purpose |
|------|---------|
| `vulnerable_app/app.py` | Flask app with one deliberate flaw per route |
| `vulnerable_app/config.py` | Hardcoded secrets / fake credentials |
| `requirements.txt` | Outdated dependencies with known CVEs (for Dependabot) |
| `.github/workflows/codeql.yml` | GitHub CodeQL analysis (`security-extended` suite) |
| `.github/workflows/semgrep.yml` | Semgrep scan, uploaded as SARIF |

## Planted vulnerabilities

| Route / file | Issue | Typical CodeQL rule |
|---|---|---|
| `/users` | SQL injection | `py/sql-injection` |
| `/ping`, `/dns` | OS command injection | `py/command-line-injection` |
| `/calc` | `eval()` on user input | `py/code-injection` |
| `/hello` | Reflected XSS | `py/reflective-xss` |
| `/greet` | Jinja2 autoescape off | `py/jinja2/autoescape-false` |
| `/download` | Path traversal | `py/path-injection` |
| `/session` | `pickle.loads` on request body | `py/unsafe-deserialization` |
| `/config` | `yaml.load` with unsafe loader | `py/unsafe-deserialization` |
| `/xml` | XXE | `py/xxe` |
| `/fetch` | SSRF | `py/full-ssrf` |
| `/fetch-insecure` | `verify=False` | `py/request-without-cert-validation` |
| `/login/callback` | Open redirect | `py/url-redirection` |
| `/register` | MD5 password hash, password logged | `py/weak-sensitive-data-hashing`, `py/clear-text-logging-sensitive-data` |
| `/debug-error` | Stack trace returned to user | `py/stack-trace-exposure` |
| `app.run(debug=True)` | Flask debug mode | `py/flask-debug` |
| `config.py` | Hardcoded secrets | Semgrep secrets rules / GitHub secret scanning |

## How to see the results

1. Push this repo to GitHub.
2. **Settings → Code security**: make sure *Code scanning* isn't set to
   "Default setup" (it would conflict with the advanced `codeql.yml` workflow).
   Optionally enable *Dependabot alerts* and *Secret scanning* too.
3. Wait for the **CodeQL** and **Semgrep** workflows to finish (Actions tab).
4. Open **Security → Code scanning**. Filter by *Tool* to compare CodeQL vs.
   Semgrep. Click an alert to see the rule help, the data-flow path
   (CodeQL "Show paths"), severity, CWE tags, and remediation guidance.
5. **Security → Dependabot** shows CVEs from `requirements.txt`.
