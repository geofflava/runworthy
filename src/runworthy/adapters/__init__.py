"""Detector adapters — each normalizes one OSS scanner's output into ``Finding``s.

Adapters prefill ``afr_controls[]`` for the mechanical mappings in spec §3 only;
judgment mappings belong to the Phase 1 interpretation layer.
"""

from . import gitleaks_adapter, osv_adapter, skillspector_adapter

#: Run order is cosmetic — findings are sorted deterministically in normalize.
ADAPTERS = (gitleaks_adapter, osv_adapter, skillspector_adapter)

__all__ = ["ADAPTERS", "gitleaks_adapter", "osv_adapter", "skillspector_adapter"]
