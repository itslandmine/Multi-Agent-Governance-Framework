"""
Role-Based Access Control (RBAC) Guardrail

- "Access Control, Encryption & Retention"
- "Role-based on every tool/connector an agent invokes"
- "Principle of least privilege - minimum scopes"
"""

from dataclasses import dataclass, field
from enum import Enum


class Permission(Enum):
    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    CALL_LLM = "call_llm"
    EXECUTE_TOOL = "execute_tool"
    ACCESS_PII = "access_pii"
    ADMIN = "admin"


@dataclass
class Role:
    name: str
    permissions: set[Permission]
    allowed_tools: set[str] = field(default_factory=set)
    max_data_scope: str = "own"  # "own", "team", "org"


# Pre-defined roles following least-privilege principle
ROLES = {
    "customer_agent": Role(
        name="customer_agent",
        permissions={Permission.READ_DATA, Permission.CALL_LLM, Permission.EXECUTE_TOOL},
        allowed_tools={"search_faq", "lookup_order", "create_ticket"},
        max_data_scope="own",
    ),
    "analyst_agent": Role(
        name="analyst_agent",
        permissions={Permission.READ_DATA, Permission.CALL_LLM, Permission.EXECUTE_TOOL},
        allowed_tools={"query_db", "generate_report", "search_faq"},
        max_data_scope="team",
    ),
    "admin_agent": Role(
        name="admin_agent",
        permissions={Permission.READ_DATA, Permission.WRITE_DATA, Permission.CALL_LLM,
                     Permission.EXECUTE_TOOL, Permission.ACCESS_PII, Permission.ADMIN},
        allowed_tools={"*"},
        max_data_scope="org",
    ),
}


@dataclass
class AccessDenied:
    agent_role: str
    attempted_action: str
    required_permission: Permission
    reason: str


class RBACEnforcer:
    """Enforces role-based access control on agent actions.

    Every tool call and data access goes through this enforcer.
    """

    def __init__(self, roles: dict[str, Role] | None = None):
        self.roles = roles or ROLES

    def check_permission(self, role_name: str, permission: Permission) -> bool:
        role = self.roles.get(role_name)
        if not role:
            return False
        return permission in role.permissions

    def check_tool_access(self, role_name: str, tool_name: str) -> bool:
        role = self.roles.get(role_name)
        if not role:
            return False
        if "*" in role.allowed_tools:
            return True
        return tool_name in role.allowed_tools

    def authorize(self, role_name: str, action: str, tool: str | None = None) -> AccessDenied | None:
        """Authorize an agent action. Returns None if allowed, AccessDenied if not."""
        role = self.roles.get(role_name)
        if not role:
            return AccessDenied(role_name, action, Permission.READ_DATA, f"Unknown role: {role_name}")

        # Map actions to required permissions
        action_permissions = {
            "read": Permission.READ_DATA,
            "write": Permission.WRITE_DATA,
            "call_llm": Permission.CALL_LLM,
            "execute_tool": Permission.EXECUTE_TOOL,
            "access_pii": Permission.ACCESS_PII,
        }

        required = action_permissions.get(action)
        if required and required not in role.permissions:
            return AccessDenied(role_name, action, required,
                                f"Role '{role_name}' lacks permission: {required.value}")

        if tool and not self.check_tool_access(role_name, tool):
            return AccessDenied(role_name, f"use tool '{tool}'", Permission.EXECUTE_TOOL,
                                f"Role '{role_name}' cannot access tool: {tool}")

        return None
