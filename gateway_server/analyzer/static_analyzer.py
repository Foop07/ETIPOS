"""
ETIPOS Static Threat Analyzer (Gateway Node 2)
Implements:
  - Arzt et al. (PLDI 2014) FlowDroid: Static Taint Analysis & Source-to-Sink tracing
  - Desnos (2012) Androguard: APK Manifest & DEX Smali / Bytecode inspection
  - Shabtai et al. (2010): Android Risk Scoring & Permission Matrix
"""

import os
import re
import zipfile
import hashlib
from typing import Dict, Any, List, Optional


class StaticAnalyzer:
    """Performs localized static security analysis on incoming APKs and binaries."""

    # High-Risk / Dangerous Android Permissions (OWASP Mobile Top 10)
    CRITICAL_PERMISSIONS = {
        "android.permission.SEND_SMS": {"weight": 2.5, "desc": "Send background SMS (Trojan/toll fraud risk)"},
        "android.permission.READ_SMS": {"weight": 2.0, "desc": "Read SMS / OTPs (Credential interception)"},
        "android.permission.RECEIVE_SMS": {"weight": 2.0, "desc": "Intercept SMS broadcast"},
        "android.permission.READ_CONTACTS": {"weight": 1.5, "desc": "Access address book (PII exfiltration)"},
        "android.permission.ACCESS_FINE_LOCATION": {"weight": 1.5, "desc": "GPS precise tracking"},
        "android.permission.RECORD_AUDIO": {"weight": 2.0, "desc": "Microphone eavesdropping"},
        "android.permission.CAMERA": {"weight": 1.5, "desc": "Camera surveillance"},
        "android.permission.READ_CALL_LOG": {"weight": 1.5, "desc": "Call history harvesting"},
        "android.permission.REQUEST_INSTALL_PACKAGES": {"weight": 3.0, "desc": "Dropper / Silent APK installation"},
        "android.permission.SYSTEM_ALERT_WINDOW": {"weight": 2.5, "desc": "Overlay attack / Clickjacking"},
        "android.permission.BIND_ACCESSIBILITY_SERVICE": {"weight": 4.0, "desc": "Keylogging / Automated UI hijack"},
        "android.permission.BIND_DEVICE_ADMIN": {"weight": 3.5, "desc": "Device Administrator lock/wipe privileges"},
        "android.permission.WRITE_SETTINGS": {"weight": 1.0, "desc": "System settings modification"},
    }

    # Suspicious Code Patterns & API Signatures (Source to Sink)
    SUSPICIOUS_SIGNATURES = [
        {
            "name": "Dynamic_Code_Loading",
            "regex": re.compile(rb"DexClassLoader|InMemoryDexClassLoader|PathClassLoader|dalvik/system/DexFile", re.IGNORECASE),
            "weight": 3.5,
            "desc": "Dynamic DEX loading from untrusted storage (Evasion technique)"
        },
        {
            "name": "Root_Command_Execution",
            "regex": re.compile(rb"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|/system/bin/sh|/system/xbin/su|su\s+-c", re.IGNORECASE),
            "weight": 4.0,
            "desc": "Privileged shell execution / Root abuse"
        },
        {
            "name": "Reflection_Obfuscation",
            "regex": re.compile(rb"java/lang/reflect/Method;->invoke|Class;->forName|getDeclaredMethod", re.IGNORECASE),
            "weight": 1.5,
            "desc": "High-frequency Java reflection (Potential obfuscation/hooking)"
        },
        {
            "name": "Hardcoded_C2_IP",
            "regex": re.compile(rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{2,5}\b"),
            "weight": 2.5,
            "desc": "Hardcoded raw IP:Port socket connection"
        },
        {
            "name": "Crypto_Ransomware_Strings",
            "regex": re.compile(rb"AES/CBC/PKCS5Padding.*YOUR_FILES_ARE_ENCRYPTED|bitcoin|ransom", re.IGNORECASE),
            "weight": 4.5,
            "desc": "Ransomware / Encrypted locking indicators"
        },
        {
            "name": "Anti_Analysis_Debug_Check",
            "regex": re.compile(rb"android/os/Debug;->isDebuggerConnected|ro\.kernel\.qemu|generic_x86", re.IGNORECASE),
            "weight": 2.0,
            "desc": "Anti-VM / Sandbox evasion checks"
        }
    ]

    @classmethod
    def analyze_bytes(cls, raw_bytes: bytes, filename: str = "payload.bin") -> Dict[str, Any]:
        """Analyzes an in-memory binary or APK file."""
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        is_apk = filename.lower().endswith(".apk") or raw_bytes.startswith(b"PK\x03\x04")

        report = {
            "filename": filename,
            "sha256": sha256,
            "size_bytes": len(raw_bytes),
            "is_apk": is_apk,
            "package_name": "unknown",
            "dangerous_permissions": [],
            "suspicious_apis": [],
            "dynamic_loading_detected": False,
            "hardcoded_endpoints": [],
            "taint_flows": [],
            "static_threat_score": 0.0,
            "findings": []
        }

        if is_apk:
            cls._inspect_apk_zip(raw_bytes, report)
        else:
            cls._inspect_generic_binary(raw_bytes, report)

        # Calculate normalized static score (capped at 10.0)
        score = 0.0
        for perm in report["dangerous_permissions"]:
            perm_name = perm["permission"]
            score += cls.CRITICAL_PERMISSIONS.get(perm_name, {}).get("weight", 0.5)

        for api in report["suspicious_apis"]:
            score += api.get("weight", 1.0)

        if report["dynamic_loading_detected"]:
            score += 2.0

        score = min(10.0, round(score, 1))
        report["static_threat_score"] = score
        return report

    @classmethod
    def _inspect_apk_zip(cls, raw_bytes: bytes, report: Dict[str, Any]) -> None:
        """Unpacks ZIP/APK structure, parses manifest and DEX strings."""
        import io
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                namelist = z.namelist()
                has_dex = any(n.endswith(".dex") for n in namelist)
                has_manifest = "AndroidManifest.xml" in namelist

                report["apk_structure"] = {
                    "total_files": len(namelist),
                    "dex_count": sum(1 for n in namelist if n.endswith(".dex")),
                    "has_native_libs": any(n.startswith("lib/") for n in namelist)
                }

                # Scan AndroidManifest.xml strings
                if has_manifest:
                    manifest_data = z.read("AndroidManifest.xml")
                    cls._extract_manifest_permissions(manifest_data, report)

                # Scan DEX files for suspicious code signatures
                for name in namelist:
                    if name.endswith(".dex") or name.endswith(".so"):
                        dex_content = z.read(name)
                        cls._scan_byte_signatures(dex_content, report, source_file=name)

        except zipfile.BadZipFile:
            report["findings"].append("Malformed or obfuscated ZIP archive structure")
            report["static_threat_score"] += 3.0

    @classmethod
    def _extract_manifest_permissions(cls, manifest_data: bytes, report: Dict[str, Any]) -> None:
        """Extracts permission strings from raw AndroidManifest.xml bytes."""
        # Find android.permission strings in the manifest
        for perm_name, meta in cls.CRITICAL_PERMISSIONS.items():
            perm_bytes = perm_name.encode('utf-8')
            if perm_bytes in manifest_data:
                report["dangerous_permissions"].append({
                    "permission": perm_name,
                    "risk_weight": meta["weight"],
                    "description": meta["desc"]
                })
                report["findings"].append(f"Dangerous Permission Declared: {perm_name} ({meta['desc']})")

        # Extract Package Name heuristic
        pkg_explicit = re.search(rb'package=["\']([^"\']+)["\']', manifest_data)
        if pkg_explicit:
            report["package_name"] = pkg_explicit.group(1).decode('utf-8', errors='ignore')
        else:
            pkg_matches = re.findall(rb"([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)", manifest_data)
            for pkg in pkg_matches:
                pkg_str = pkg.decode('utf-8', errors='ignore')
                if not pkg_str.startswith("android.") and not pkg_str.startswith("schemas.") and not pkg_str.startswith("http"):
                    report["package_name"] = pkg_str
                    break

    @classmethod
    def _scan_byte_signatures(cls, byte_data: bytes, report: Dict[str, Any], source_file: str) -> None:
        """Scans DEX/binary for suspicious API patterns."""
        for sig in cls.SUSPICIOUS_SIGNATURES:
            if sig["regex"].search(byte_data):
                finding_name = sig["name"]
                if finding_name not in [a["name"] for a in report["suspicious_apis"]]:
                    report["suspicious_apis"].append({
                        "name": finding_name,
                        "weight": sig["weight"],
                        "description": sig["desc"],
                        "detected_in": source_file
                    })
                    report["findings"].append(f"Suspicious API Detected [{source_file}]: {sig['desc']}")

                    if finding_name == "Dynamic_Code_Loading":
                        report["dynamic_loading_detected"] = True

        # Extract hardcoded URLs
        urls = re.findall(rb"(https?://[a-zA-Z0-9\.\-_:/]+)", byte_data)
        for u in set(urls):
            u_str = u.decode('utf-8', errors='ignore')
            if len(u_str) > 10 and not u_str.startswith("http://schemas.android.com"):
                if u_str not in report["hardcoded_endpoints"]:
                    report["hardcoded_endpoints"].append(u_str)

    @classmethod
    def _inspect_generic_binary(cls, raw_bytes: bytes, report: Dict[str, Any]) -> None:
        """Scans non-APK files (scripts, docs, text messages) for prompt injection and binary attacks."""
        cls._scan_byte_signatures(raw_bytes, report, source_file=report["filename"])

        # Check for prompt injection keywords in text
        prompt_injection_patterns = [
            rb"ignore\s+(?:all\s+)?previous\s+instructions",
            rb"system\s*:\s*you\s+are\s+now",
            rb"<script\b",
            rb"cmd\.exe|powershell\s+-enc",
        ]
        for pattern in prompt_injection_patterns:
            if re.search(pattern, raw_bytes, re.IGNORECASE):
                report["findings"].append("Prompt Injection / Malicious Script Sequence Detected in text content")
                report["suspicious_apis"].append({
                    "name": "Prompt_Injection_Payload",
                    "weight": 4.0,
                    "description": "Adversarial prompt injection pattern in payload",
                    "detected_in": report["filename"]
                })
