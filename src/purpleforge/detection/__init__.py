"""Blue-team layer: rule loading and the detection engine."""

from purpleforge.detection.engine import DetectionEngine
from purpleforge.detection.loader import load_rule, load_all_rules, RULES_DIR

__all__ = ["DetectionEngine", "load_rule", "load_all_rules", "RULES_DIR"]
