"""
integrations/__init__.py — Integration provider registry.

Currently supports Jira. ServiceNow and Azure DevOps can be added
as additional modules following the same pattern.
"""

from .jira import JiraClient, format_finding_for_jira

__all__ = ["JiraClient", "format_finding_for_jira"]
