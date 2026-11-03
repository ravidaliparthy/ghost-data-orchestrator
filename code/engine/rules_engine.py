"""
ConfigurableRulesEngine — Deletion Policy Engine.
"""
import json
import os
from typing import Dict, Any, List, Optional, Tuple
from .common import load_csv, parse_utc


class Rule:
    def __init__(self, rule_id: str, data_category: str, condition: str, required_action: str):
        self.rule_id = rule_id
        self.data_category = data_category
        self.condition = condition
        self.required_action = required_action

    def matches_category(self, category: str) -> bool:
        return self.data_category == category

    def is_retain(self) -> bool:
        return self.required_action == "RETAIN"

    def is_delete(self) -> bool:
        return self.required_action == "DELETE"

    def is_redact(self) -> bool:
        return self.required_action == "REDACT"

    def is_anonymize(self) -> bool:
        return self.required_action == "ANONYMIZE"

    def condition_holds(self, context: Dict[str, Any], audit_at) -> bool:
        cond = self.condition.strip()
        if cond == "Always":
            return True
        if cond == "Record is still attributable to a user":
            return context.get("attributable_to_user", False)
        if cond == "Conversation contains shared customer, agent, or order context that must be retained":
            return context.get("shared_context", False)
        if cond == "Attachment belongs only to the deletion subject":
            return context.get("attachment_only_subject", True)
        if cond == "A supplied legal hold is active":
            return context.get("legal_hold_active", False)
        if cond == "Restore access can be blocked":
            return context.get("restore_access_blockable", True)
        if cond == "Record is within the supplied retention period":
            retention_until = context.get("retention_until")
            if retention_until is None:
                return False
            rt = parse_utc(retention_until)
            if rt is None:
                return False
            return rt > audit_at
        if cond == "Account is deleted and only a stable internal user_id is needed to preserve references to retained records":
            return context.get("tombstone_needed", False)
        if cond == "Log contains a user email address":
            return context.get("log_contains_email", False) or context.get("attributable_to_user", False)
        return False


class ConfigurableRulesEngine:
    def __init__(self, rules_csv_path: str, overrides_json_path: Optional[str] = None):
        self.rules_csv_path = rules_csv_path
        self.overrides_json_path = overrides_json_path
        self.rules: List[Rule] = []
        self.overrides: Dict[str, Any] = {}
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        rows = load_csv(self.rules_csv_path)
        for row in rows:
            rule = Rule(
                rule_id=row.get("rule_id", ""),
                data_category=row.get("data_category", ""),
                condition=row.get("condition", "Always"),
                required_action=row.get("required_action", "DELETE"),
            )
            self.rules.append(rule)

        if self.overrides_json_path and os.path.exists(self.overrides_json_path):
            with open(self.overrides_json_path, "r", encoding="utf-8") as f:
                self.overrides = json.load(f)
            overrides_rules = self.overrides.get("rule_overrides", {})
            for rule_id, override in overrides_rules.items():
                for rule in self.rules:
                    if rule.rule_id == rule_id:
                        if "required_action" in override:
                            rule.required_action = override["required_action"]
                        break

        self._loaded = True

    def required_action_for(self, data_category: str, context: Dict[str, Any], audit_at) -> Optional[str]:
        matching: List[Rule] = []
        for rule in self.rules:
            if rule.matches_category(data_category) and rule.condition_holds(context, audit_at):
                matching.append(rule)

        if not matching:
            return None

        for rule in matching:
            if rule.is_retain():
                return "RETAIN"

        priority = {"DELETE": 0, "REDACT": 1, "ANONYMIZE": 2}
        matching.sort(key=lambda r: priority.get(r.required_action, 99))
        return matching[0].required_action

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def is_retain_category(self, data_category: str) -> bool:
        for rule in self.rules:
            if rule.matches_category(data_category):
                return rule.is_retain()
        return False