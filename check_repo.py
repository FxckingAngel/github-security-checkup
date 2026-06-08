import json
import os
import sys
import urllib.error
import urllib.request


API = "https://api.github.com"
WORKFLOW_PERMISSION_KEYS = ("actions", "contents", "deployments", "id-token", "issues", "packages", "pull-requests")


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


def content_status(owner, repo, path):
    status, data = request_json(f"/repos/{owner}/{repo}/contents/{path}")
    if status == 200:
        return "present"
    if status == 404:
        return "missing"
    return f"unknown ({status}: {data.get('message', 'no message')})"


def license_status(data):
    license_info = data.get("license")
    if not license_info:
        return "missing"
    return license_info.get("spdx_id") or license_info.get("key") or "present"


def workflows_status(owner, repo):
    status, data = request_json(f"/repos/{owner}/{repo}/actions/workflows")
    if status == 404:
        return "none or not visible"
    if status != 200:
        return f"unknown ({status}: {data.get('message', 'no message')})"
    return data.get("total_count", 0)


def workflow_permission_hints(owner, repo):
    status, data = request_json(f"/repos/{owner}/{repo}/contents/.github/workflows")
    if status == 404:
        return "no workflow directory"
    if status != 200:
        return f"unknown ({status}: {data.get('message', 'no message')})"

    workflow_files = [
        item["path"]
        for item in data
        if item.get("type") == "file" and item.get("name", "").endswith((".yml", ".yaml"))
    ]
    if not workflow_files:
        return "no workflow files"

    missing_permissions = []
    broad_permissions = []
    for path in workflow_files:
        file_status, file_data = request_json(f"/repos/{owner}/{repo}/contents/{path}")
        if file_status != 200:
            continue

        raw_url = file_data.get("download_url")
        if not raw_url:
            continue

        req = urllib.request.Request(raw_url)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                text = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError:
            continue

        lower_text = text.lower()
        if "permissions:" not in lower_text:
            missing_permissions.append(path)
        if any(f"{key}: write" in lower_text for key in WORKFLOW_PERMISSION_KEYS) or "write-all" in lower_text:
            broad_permissions.append(path)

    return {
        "workflow_files": workflow_files,
        "missing_permissions_block": missing_permissions,
        "write_permissions": broad_permissions,
    }


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
        "license": license_status(data),
        "security_policy": content_status(owner, repo, "SECURITY.md"),
        "dependabot_config": content_status(owner, repo, ".github/dependabot.yml"),
        "workflow_count": workflows_status(owner, repo),
        "workflow_permission_hints": workflow_permission_hints(owner, repo),
    }

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
