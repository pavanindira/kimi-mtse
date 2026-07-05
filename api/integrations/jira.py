"""
integrations/jira.py — Jira REST API client for ticket creation.

Supports Jira Cloud and Jira Server/Data Center.
Authentication: API token (Cloud) or PAT (Server).

Usage:
    client = JiraClient(base_url, auth_token)
    ticket = await client.create_issue(project_key, summary, description, ...)
"""

import base64
import json
from typing import Any

import aiohttp


class JiraClient:
    def __init__(self, base_url: str, auth_token: str, email: str = ""):
        """
        Args:
            base_url:  Jira instance URL, e.g. https://your-domain.atlassian.net
            auth_token: API token (Cloud) or PAT (Server)
            email:     User email (required for Cloud API token auth)
        """
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.email = email

    def _headers(self) -> dict[str, str]:
        if self.email:
            # Cloud: Basic auth with email + API token
            creds = base64.b64encode(
                f"{self.email}:{self.auth_token}".encode()
            ).decode()
            return {
                "Authorization": f"Basic {creds}",
                "Content-Type": "application/json",
            }
        else:
            # Server: Bearer token (PAT)
            return {
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            }

    async def create_issue(
        self,
        project_key: str,
        summary: str,
        description: str,
        issue_type: str = "Bug",
        priority: str | None = None,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a Jira issue and return the created issue dict."""
        url = f"{self.base_url}/rest/api/2/issue"

        fields: dict[str, Any] = {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
        }
        if priority:
            fields["priority"] = {"name": priority}
        if labels:
            fields["labels"] = labels

        payload = {"fields": fields}

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, headers=self._headers(), json=payload, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                text = await resp.text()
                if resp.status not in (200, 201):
                    raise RuntimeError(
                        f"Jira create_issue failed: HTTP {resp.status} — {text}"
                    )
                return json.loads(text)

    async def get_issue(self, issue_key: str) -> dict[str, Any]:
        """Fetch a single issue by key."""
        url = f"{self.base_url}/rest/api/2/issue/{issue_key}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers(), timeout=aiohttp.ClientTimeout(total=30)) as resp:
                text = await resp.text()
                if resp.status != 200:
                    raise RuntimeError(f"Jira get_issue failed: HTTP {resp.status} — {text}")
                return json.loads(text)

    async def add_comment(self, issue_key: str, body: str) -> dict[str, Any]:
        """Add a comment to an existing issue."""
        url = f"{self.base_url}/rest/api/2/issue/{issue_key}/comment"
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, headers=self._headers(), json={"body": body}, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                text = await resp.text()
                if resp.status not in (200, 201):
                    raise RuntimeError(f"Jira add_comment failed: HTTP {resp.status} — {text}")
                return json.loads(text)


def format_finding_for_jira(finding: dict[str, Any], engagement_name: str = "") -> str:
    """Convert a finding dict into a Jira-compatible description string."""
    lines = [
        f"*Severity:* {finding.get('severity', 'Unknown')}",
        f"*Tool:* {finding.get('tool', 'Unknown')}",
        f"*CVSS Score:* {finding.get('cvss_score') or 'N/A'}",
        f"*Status:* {finding.get('status', 'Open')}",
        "",
    ]
    if finding.get('target_url'):
        lines.append(f"*Target URL:* {finding['target_url']}")
    if finding.get('file_path'):
        lines.append(f"*File:* {finding['file_path']}{f':{finding['line_number']}' if finding.get('line_number') else ''}")
    if finding.get('host'):
        lines.append(f"*Host:* {finding['host']}{f':{finding['port']}' if finding.get('port') else ''}")
    if finding.get('cve_id'):
        lines.append(f"*CVE:* {finding['cve_id']}")
    if finding.get('cwe_id'):
        lines.append(f"*CWE:* {finding['cwe_id']}")

    lines.append("")
    lines.append("*Description:*")
    lines.append(finding.get('description') or 'No description provided.')
    lines.append("")
    lines.append("*Remediation:*")
    lines.append(finding.get('remediation') or 'No remediation guidance provided.')

    if engagement_name:
        lines.insert(0, f"*Engagement:* {engagement_name}")
        lines.insert(1, "")

    return "\n".join(lines)
