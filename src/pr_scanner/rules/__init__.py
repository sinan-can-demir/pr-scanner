"""Detection rules. Each rule is a pure function of a Diff (docs/05-architecture.md)."""

from __future__ import annotations

from .dropper import RemoteBinaryExec
from .hooks import NpmLifecycleHook, PyBuildBackend, PySetupHook
from .registry import Registry
from .scanner import ScannerTamper
from .workflows import (
    ActionPinning,
    PermissionsWidening,
    PipeToShell,
    PullRequestTargetCheckout,
    ScriptInjection,
    SecretExposure,
)

ALL_RULES = (
    NpmLifecycleHook,
    PySetupHook,
    PyBuildBackend,
    RemoteBinaryExec,
    PullRequestTargetCheckout,
    ActionPinning,
    PermissionsWidening,
    SecretExposure,
    PipeToShell,
    ScriptInjection,
    ScannerTamper,
)


def default_registry() -> Registry:
    """Explicit registration only; rules are never discovered from PR content."""
    reg = Registry()
    for rule_cls in ALL_RULES:
        reg.register(rule_cls())
    return reg
