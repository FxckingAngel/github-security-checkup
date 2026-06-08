import json
import os
import sys
import urllib.error
import urllib.request


API = "https://api.github.com"


def request_json(path):
    token = os.environ.get("GITHUB_TOKEN")
    req = urllib.request.Request(f"{API}{path}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {"message": body}
        return error.code, data


def protection_status(owner, repo, branch):
    status, data = request_json(f"/repos/{owner}/{repo}/branches/{branch}/protection")
    if status == 200:
        return "enabled"
    if status == 404:
        return "not enabled or not visible"
    return f"unknown ({status}: {data.get('message', 'no message')})"


def main():
    if len(sys.argv) != 2 or "/" not in sys.argv[1]:
        print("usage: python check_repo.py owner/repo")
        return 2

    owner, repo = sys.argv[1].split("/", 1)
    status, data = request_json(f"/repos/{owner}/{repo}")
    if status != 200:
        print(f"failed to fetch repo: {status} {data.get('message', 'no message')}")
        return 1

    default_branch = data["default_branch"]
    report = {
        "repo": data["full_name"],
        "visibility": data.get("visibility"),
        "private": data["private"],
        "archived": data["archived"],
        "default_branch": default_branch,
        "open_issues": data["open_issues_count"],
        "pushed_at": data["pushed_at"],
        "branch_protection": protection_status(owner, repo, default_branch),
    }

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

