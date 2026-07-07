"""Runworthy — an agent operations scanner.

Scans a repo for AI-agent security and operational-safety gaps and (Phase 1+)
grades it against the Agent Flight Rules (AFR). Phase 0 is the deterministic
core: fingerprint + three contained detector adapters → a provisional,
self-contained ``ReadinessReport``. No LLM in this layer.
"""

from __future__ import annotations

__version__ = "0.2.0"

from .engine import scan
from .models import Finding, ReadinessReport, ScanTarget

__all__ = ["__version__", "scan", "Finding", "ReadinessReport", "ScanTarget"]
