"""Rule registry: explicit registration, no dynamic discovery of PR content."""

from __future__ import annotations

from .base import Rule


class DuplicateRuleError(ValueError):
    pass


class Registry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        if rule.id in self._rules:
            raise DuplicateRuleError(f"rule id already registered: {rule.id}")
        self._rules[rule.id] = rule

    def rules(self) -> list[Rule]:
        """Rules in stable id order (NFR-07)."""
        return [self._rules[k] for k in sorted(self._rules)]
