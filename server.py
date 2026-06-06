"""red-team-ops-mcp — MEOK AI Labs.

Mobile red-team toolkit: decompile APKs, extract endpoints and API call
sites, scan for hardcoded secrets, and pull APK metadata (package, version,
permissions, exported activities). Pure-Python (pyjadx + androguard).

Tools:
  - decompile_apk(apk_path)
  - extract_endpoints(apk_path)
  - find_api_calls(apk_path)
  - scan_hardcoded_secrets(apk_path)
  - apk_metadata(apk_path)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "red-team-ops",
    instructions=(
        "Mobile red-team / app-assessment toolkit for Android APKs. "
        "Decompile APKs to Java source, extract HTTP endpoints and API call "
        "sites, scan decompiled source for hardcoded secrets, and pull APK "
        "metadata (package, version, permissions, exported activities, "
        "intent filters). All tools are pure-Python (pyjadx + androguard); "
        "no jadx / apktool on PATH required."
    ),
)

# ---------- patterns ---------------------------------------------------------

_RETROFIT_HTTP = re.compile(
    r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\(\s*\"([^\"]+)\""
)
_OKHTTP_BUILDER = re.compile(r"\.url\(\s*\"([^\"]+)\"")
_OKHTTP_HTTP_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+")
_API_KEY_LITERAL = re.compile(
    r"(?i)(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-/.+=]{12,}['\"]"
)
_AWS_ACCESS = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_FIREBASE_URL = re.compile(r"https?://[A-Za-z0-9-]+\.firebaseio\.com")
_FIREBASE_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

# ---------- decompile helper ------------------------------------------------


def _decompile(apk_path: str) -> Dict[str, Any]:
    """Run pyjadx; return ``{class: source}`` or error dict."""
    if not os.path.isfile(apk_path):
        return {"_error": f"file not found: {apk_path}"}
    try:
        from pyjadx import Jadx  # type: ignore
    except ImportError:
        return {
            "_error": "pyjadx not installed",
            "install": "pip install pyjadx",
        }
    try:
        jadx = Jadx()
        jadx.load(apk_path)
        out: Dict[str, str] = {}
        for cls in jadx.classes:
            try:
                src = cls.source or ""
                if len(src) > 80_000:
                    src = src[:80_000] + "\n... (truncated)"
                out[getattr(cls, "full_name", "?")] = src
            except Exception:
                continue
        return {"_sources": out}
    except Exception as e:
        return {"_error": f"pyjadx failed: {e}"}


# ---------- tool: decompile_apk ---------------------------------------------


@mcp.tool(name="decompile_apk")
async def decompile_apk(apk_path: str) -> dict:
    """Decompile an APK into Java source via pyjadx.

    Returns a list of ``{class, source}`` (source truncated at 80 KB / class).
    """
    decomp = _decompile(apk_path)
    if "_error" in decomp:
        return {"apk_path": apk_path, "error": decomp["_error"]}
    sources = decomp["_sources"]
    out = [{"class": k, "source": v} for k, v in sources.items()]
    return {
        "apk_path": apk_path,
        "class_count": len(out),
        "classes": out,
    }


# ---------- tool: extract_endpoints ----------------------------------------


@mcp.tool(name="extract_endpoints")
async def extract_endpoints(apk_path: str) -> dict:
    """Extract HTTP endpoints and URL literals from an APK.

    Pulls Retrofit annotations (@GET/@POST/...) and OkHttp ``.url("...")``
    calls; groups findings by decompiled class.
    """
    decomp = _decompile(apk_path)
    if "_error" in decomp:
        return {"apk_path": apk_path, "error": decomp["_error"]}
    by_class: Dict[str, List[dict]] = {}
    total = 0
    for cls_name, src in decomp["_sources"].items():
        hits: List[dict] = []
        for m in _RETROFIT_HTTP.finditer(src):
            line = src.count("\n", 0, m.start()) + 1
            hits.append({"line": line, "method": m.group(1).upper(),
                         "path": m.group(2), "kind": "retrofit"})
        for m in _OKHTTP_BUILDER.finditer(src):
            line = src.count("\n", 0, m.start()) + 1
            hits.append({"line": line, "method": "URL",
                         "path": m.group(1), "kind": "okhttp-builder"})
        for m in _OKHTTP_HTTP_URL.finditer(src):
            line = src.count("\n", 0, m.start()) + 1
            if m.group(0).endswith("/"):
                continue
            hits.append({"line": line, "method": "URL",
                         "path": m.group(0), "kind": "httpurl-literal"})
        if hits:
            by_class[cls_name] = hits
            total += len(hits)
    return {
        "apk_path": apk_path,
        "endpoint_count": total,
        "by_class": by_class,
    }


# ---------- tool: find_api_calls -------------------------------------------


@mcp.tool(name="find_api_calls")
async def find_api_calls(apk_path: str) -> dict:
    """Group decompiled HTTP call sites by enclosing class/method.

    Returns a map ``class -> method -> [endpoints]`` so a red-teamer can
    map an attack surface onto a UI/Activity flow.
    """
    decomp = _decompile(apk_path)
    if "_error" in decomp:
        return {"apk_path": apk_path, "error": decomp["_error"]}
    grouped: Dict[str, Dict[str, List[dict]]] = {}
    for cls_name, src in decomp["_sources"].items():
        cls_methods: Dict[str, List[dict]] = {}
        # Naive method splitter — Java method headers are the
        # "modifiers type name(...) {" pattern, but we just use brace depth
        # so we don't depend on full Java parsing here.
        depth = 0
        method_name = "<init>"
        method_start = 0
        last_brace_open = -1
        for i, ch in enumerate(src):
            if ch == "{":
                if depth == 0:
                    # Peek back for the method name
                    head = src[max(0, i - 200):i]
                    m = re.search(r"\b(\w+)\s*\([^)]*\)\s*$", head.rstrip())
                    if m and m.group(1) not in {"if", "for", "while", "switch",
                                                "class", "interface", "enum",
                                                "catch", "synchronized", "do"}:
                        method_name = m.group(1)
                    method_start = i
                    last_brace_open = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body = src[method_start:i + 1]
                    hits: List[dict] = []
                    for m in _RETROFIT_HTTP.finditer(body):
                        hits.append({"line": src.count("\n", 0, method_start + m.start()) + 1,
                                     "method": m.group(1).upper(),
                                     "path": m.group(2), "kind": "retrofit"})
                    for m in _OKHTTP_BUILDER.finditer(body):
                        hits.append({"line": src.count("\n", 0, method_start + m.start()) + 1,
                                     "method": "URL", "path": m.group(1),
                                     "kind": "okhttp-builder"})
                    if hits:
                        cls_methods[method_name] = hits
                    method_name = "<init>"
        if cls_methods:
            grouped[cls_name] = cls_methods
    total = sum(len(v) for cls in grouped.values() for v in cls.values())
    return {"apk_path": apk_path, "api_call_count": total, "by_class": grouped}


# ---------- tool: scan_hardcoded_secrets ----------------------------------


@mcp.tool(name="scan_hardcoded_secrets")
async def scan_hardcoded_secrets(apk_path: str) -> dict:
    """Decompile an APK and regex-sweep for hardcoded credentials.

    Returns findings grouped by pattern with class + line + redacted preview.
    """
    decomp = _decompile(apk_path)
    if "_error" in decomp:
        return {"apk_path": apk_path, "error": decomp["_error"]}
    findings: Dict[str, List[dict]] = {}
    patterns: Dict[str, re.Pattern] = {
        "aws_access_key_id": _AWS_ACCESS,
        "firebase_db_url": _FIREBASE_URL,
        "firebase_api_key": _FIREBASE_KEY,
        "api_key_literal": _API_KEY_LITERAL,
    }
    for cls_name, src in decomp["_sources"].items():
        for pname, pat in patterns.items():
            for m in pat.finditer(src):
                line = src.count("\n", 0, m.start()) + 1
                matched = m.group(0)
                if len(matched) > 24:
                    preview = matched[:6] + "…" + matched[-4:]
                else:
                    preview = matched[:8] + "…"
                findings.setdefault(pname, []).append({
                    "class": cls_name,
                    "line": line,
                    "preview": preview,
                })
    findings = {k: v for k, v in findings.items() if v}
    total = sum(len(v) for v in findings.values())
    return {
        "apk_path": apk_path,
        "total_findings": total,
        "by_pattern": findings,
    }


# ---------- tool: apk_metadata -------------------------------------------


@mcp.tool(name="apk_metadata")
async def apk_metadata(apk_path: str) -> dict:
    """Pull APK metadata via androguard (pure-Python APK parsing).

    Returns package name, version (Name + Code), min/target SDK, declared
    permissions, and the list of activities, services, and receivers.
    """
    if not os.path.isfile(apk_path):
        return {"apk_path": apk_path, "error": "file not found"}
    try:
        from androguard.core.apk import APK  # type: ignore
    except ImportError:
        return {
            "apk_path": apk_path,
            "error": "androguard not installed",
            "install": "pip install androguard",
        }
    try:
        apk = APK(apk_path)
        activities = sorted(apk.get_activities() or [])
        services = sorted(apk.get_services() or [])
        receivers = sorted(apk.get_receivers() or [])
        providers = sorted(apk.get_providers() or [])
        permissions = sorted(
            (apk.get_permissions() or []) +
            (apk.get_uses_implied_permissions_list() or [])
        )
        return {
            "apk_path": apk_path,
            "package": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "permissions": permissions,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "is_debuggable": apk.get_attribute_value("application", "android:debuggable"),
        }
    except Exception as e:
        return {"apk_path": apk_path, "error": f"androguard parse failed: {e}"}


# ---------- entry point --------------------------------------------------


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
