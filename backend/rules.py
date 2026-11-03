"""Loader for the configurable detection rules, scoring weights and parameters (detection_rules.json)."""
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from backend.catalog import STAGES
from backend.config import get_settings


@dataclass(frozen=True)
class RuleConfig:
    id: str
    enabled: bool
    severity: float
    stages: tuple[str, ...]
    description: str


class RulesError(ValueError):
    pass


@lru_cache
def _raw() -> dict:
    path = Path(get_settings().detection_rules_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in ("scoring", "parameters", "rules"):
        if key not in data:
            raise RulesError(f"{path.name}: missing '{key}' section")
    return data


def reload_rules() -> None:
    _raw.cache_clear()
    rules.cache_clear()


@lru_cache
def rules() -> dict[str, RuleConfig]:
    result = {}
    for rule_id, cfg in _raw()["rules"].items():
        stages = tuple(cfg.get("stages", []))
        unknown = [s for s in stages if s not in STAGES]
        severity = float(cfg["severity"])
        if unknown or not 0.0 <= severity <= 1.0:
            raise RulesError(f"rule '{rule_id}': invalid severity or stage {unknown}")
        result[rule_id] = RuleConfig(rule_id, bool(cfg.get("enabled", True)), severity, stages, cfg.get("description", rule_id))
    return result


def rule(rule_id: str) -> RuleConfig:
    return rules()[rule_id]


def param(name: str):
    return _raw()["parameters"][name]


def scoring(name: str):
    return _raw()["scoring"][name]


def weights() -> dict[str, float]:
    """Component weights, normalised to sum to 1 so the confidence score is bounded by construction."""
    raw = _raw()["scoring"]["weights"]
    total = sum(raw.values())
    return {k: v / total for k, v in raw.items()}


def stage_weight(stage: str) -> float:
    return float(_raw()["scoring"]["stage_weights"].get(stage, 0.0))


def summary() -> dict:
    return {
        "path": Path(get_settings().detection_rules_path).name,
        "scoring": _raw()["scoring"],
        "parameters": _raw()["parameters"],
        "rules": {rid: {"enabled": r.enabled, "severity": r.severity, "stages": list(r.stages), "description": r.description}
                  for rid, r in rules().items()},
    }
