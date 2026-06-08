# GitHub Security Checkup

Small CLI for checking basic GitHub repository security and hygiene signals.

It uses the GitHub REST API and reports:

- repository visibility
- default branch
- archived status
- open issue count
- last pushed date
- default branch protection status

## Use

```bash
python check_repo.py owner/repo
```

For higher rate limits or private repos, set a GitHub token first:

```bash
# Windows PowerShell
$env:GITHUB_TOKEN = "ghp_your_token_here"
python check_repo.py owner/repo
```

```bash
# macOS / Linux
export GITHUB_TOKEN="ghp_your_token_here"
python check_repo.py owner/repo
```

## Example

```bash
python check_repo.py FxckingAngel/github-security-checkup
```

```json
{
  "repo": "FxckingAngel/github-security-checkup",
  "visibility": "public",
  "private": false,
  "archived": false,
  "default_branch": "main",
  "open_issues": 0,
  "pushed_at": "2026-06-08T01:31:22Z",
  "branch_protection": "not enabled or not visible"
}
```

## Why

This is a quick first pass before a deeper repo review.

It does not replace a real security audit. It helps spot basic repo hygiene issues fast.

## Checks To Add

- license detection
- Dependabot config check
- security policy check
- workflow permissions check
- branch protection details when visible

## License

MIT
