"""Normalization invariants (toolless): drop-no-location, id stability,
dedup/merge, severity max."""

from __future__ import annotations

from runworthy.models import Confidence, Finding, Severity
from runworthy.normalize import dep_dedup_key, finalize, resolve_manifest_line


def _finding(**kw) -> Finding:
    base = dict(
        finding_id="",
        detector="osv-scanner",
        detector_version="2.4.0",
        afr_controls=["AFR-10"],
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file="requirements.txt",
        line=1,
        snippet_redacted="pkg==1.0",
        raw_message="msg",
        dedup_key="dep::pypi::pkg::requirements.txt",
    )
    base.update(kw)
    return Finding(**base)


def test_drops_finding_without_location():
    out, dropped = finalize([_finding(file="", line=0, dedup_key="code::X::none::0")])
    assert out == []
    assert dropped == 1


def test_id_is_stable_and_content_derived():
    out, _ = finalize([_finding(dedup_key="code::AST4::a.py::5")])
    assert out[0].finding_id == Finding.make_id("code::AST4::a.py::5")
    # same key -> same id across runs
    assert out[0].finding_id == Finding.make_id("code::AST4::a.py::5")


def test_osv_and_skillspector_same_dep_merge_to_one(  ):
    """Invariant 4 / criterion 6 at the unit level."""
    key = dep_dedup_key("PyPI", "requests", "requirements.txt")
    osv = _finding(detector="osv-scanner", severity=Severity.HIGH, dedup_key=key, afr_controls=["AFR-10"])
    ss = _finding(
        detector="skillspector",
        detector_version="2.3.9",
        severity=Severity.MEDIUM,
        dedup_key=key,
        afr_controls=["AFR-10"],
        raw_message="ss SC4 requests",
    )
    out, _ = finalize([ss, osv])  # order-independent
    assert len(out) == 1
    merged = out[0]
    assert merged.detector == "osv-scanner"  # authoritative primary
    assert "skillspector" in merged.also_reported_by
    assert merged.severity == Severity.HIGH  # max severity wins
    assert merged.afr_controls == ["AFR-10"]


def test_distinct_keys_do_not_merge():
    a = _finding(dedup_key="dep::pypi::a::requirements.txt")
    b = _finding(dedup_key="dep::pypi::b::requirements.txt")
    out, _ = finalize([a, b])
    assert len(out) == 2


def test_output_order_is_deterministic():
    a = _finding(file="b.py", line=2, dedup_key="code::X::b.py::2")
    b = _finding(file="a.py", line=9, dedup_key="code::X::a.py::9")
    c = _finding(file="a.py", line=1, dedup_key="code::X::a.py::1")
    out, _ = finalize([a, b, c])
    assert [f.file for f in out] == ["a.py", "a.py", "b.py"]
    assert [f.line for f in out] == [1, 9, 2]


# runworthy#2: the rendered evidence promise is "open the cited line, see the
# package". @ and / delimit tokens, so a substring pass anchored `hono` to
# `@hono/node-server`'s entry, ~1400 lines early on a real lockfile.
_LOCKFILE = """{
  "packages": {
    "node_modules/@hono/node-server": {
      "version": "1.19.11",
      "peerDependencies": {
        "hono": "^4.0.0"
      }
    },
    "node_modules/hono": {
      "version": "4.12.8"
    }
  }
}
"""


def test_lockfile_entry_key_beats_scoped_lookalike(tmp_path):
    (tmp_path / "package-lock.json").write_text(_LOCKFILE, encoding="utf-8")
    assert resolve_manifest_line(tmp_path, "package-lock.json", "hono") == 9
    assert resolve_manifest_line(tmp_path, "package-lock.json", "@hono/node-server") == 3


def test_manifest_dependency_key_and_token_fallback(tmp_path):
    (tmp_path / "package.json").write_text(
        '{\n  "dependencies": {\n    "zod": "^3.0.0"\n  }\n}\n', encoding="utf-8"
    )
    assert resolve_manifest_line(tmp_path, "package.json", "zod") == 3
    (tmp_path / "pyproject.toml").write_text(
        'dependencies = [\n  "langchain-community>=0.3",\n]\n', encoding="utf-8"
    )
    # no exact JSON key in TOML -> the delimited-token fallback still resolves
    assert resolve_manifest_line(tmp_path, "pyproject.toml", "langchain_community") == 2
