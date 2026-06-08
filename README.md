# GitHub Security Checkup

Small CLI for checking basic GitHub repository security signals.

It uses the GitHub REST API to report:

- repository visibility
- default branch
- archived status
- open issue count
- pushed date
- default branch protection status

## Use

```bash
python check_repo.py owner/repo
```

For higher rate limits or private repos:

```bash
set GITHUB_TOKEN=ghp_your_token_here
python check_repo.py owner/repo
```

## Notes

This is a lightweight check, not a full security scanner.

It is meant for quick repo hygiene checks before deeper review.

