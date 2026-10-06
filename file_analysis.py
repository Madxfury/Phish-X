"""Static APK / PDF analysis. Also runs as an isolated, time-bounded upload worker."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import zipfile


def inspect_apk(path: str) -> dict:
    from androguard.core.apk import APK
    from loguru import logger
    logger.disable("androguard")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 5000 or sum(e.file_size for e in entries) > 64 * 1024 * 1024 or any(e.file_size > 16 * 1024 * 1024 or e.file_size > max(1024 * 1024, e.compress_size * 100) for e in entries):
            raise ValueError("APK archive exceeds safe inspection limits.")
        if "AndroidManifest.xml" not in archive.namelist():
            raise ValueError("APK is missing AndroidManifest.xml.")
    apk = APK(path, skip_analysis=False)
    if not apk.is_valid_APK() or not apk.get_package():
        raise ValueError("APK manifest is invalid.")
    permissions = sorted(set(apk.get_permissions()))
    basic = {"Package Name": apk.get_package(), "Version Name": apk.get_androidversion_name(), "Version Code": apk.get_androidversion_code(),
             "Min SDK": apk.get_min_sdk_version(), "Target SDK": apk.get_target_sdk_version(), "Permissions": len(permissions)}
    findings, risks = [], []
    sensitive = {"android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW"}
    for permission in permissions:
        if permission in sensitive:
            findings.append("Requests sensitive permission: " + permission)
    if "android.permission.INTERNET" in permissions:
        findings.append("Manifest declares Internet access.")
    manifest = apk.get_android_manifest_xml()
    ns = "{http://schemas.android.com/apk/res/android}"
    application = manifest.find("application")
    if application is not None:
        if application.get(ns + "debuggable") == "true":
            findings.append("Manifest explicitly enables debugging.")
            risks.append("Debugging is enabled; review before production use.")
        if application.get(ns + "allowBackup") == "true":
            findings.append("Manifest explicitly enables application backup.")
        if application.get(ns + "usesCleartextTraffic") == "true":
            findings.append("Manifest explicitly allows cleartext network traffic.")
            risks.append("Cleartext traffic is allowed; actual runtime traffic was not observed.")
        for kind in ("activity", "service", "receiver", "provider"):
            exported = [element.get(ns + "name", "Unnamed") for element in application.findall(kind) if element.get(ns + "exported") == "true"]
            if exported:
                findings.append(f"Explicitly exported {kind} components: " + ", ".join(exported[:30]))
    libraries = [e.filename for e in entries if e.filename.startswith("lib/") and e.filename.endswith(".so")]
    if libraries:
        findings.append(f"Archive contains {len(libraries)} native libraries; native code was not executed.")
    return {"basic_info": basic, "permissions": permissions, "security_analysis": findings, "risks": risks,
            "limitations": ["Static APK manifest and archive inspection only. Not AI analysis, a malware verdict, dynamic execution, or exhaustive DEX review."]}


def inspect_pdf(path: str) -> dict:
    from pypdf import PdfReader
    from pypdf.generic import DictionaryObject, ArrayObject, IndirectObject
    reader = PdfReader(path, strict=False)
    encrypted = reader.is_encrypted
    if encrypted and not reader.decrypt(""):
        return {"basic_info": {"Encrypted": True, "File Size": f"{Path(path).stat().st_size / 1024:.2f} KB"}, "metadata": {},
                "security_analysis": ["Document requires a password; content could not be inspected."], "risks": [], "javascript": [], "actions": [], "status": "partial", "limitations": ["Encrypted PDF contents unavailable."]}
    if len(reader.pages) > 300:
        raise ValueError("PDF exceeds the 300-page inspection limit.")
    metadata = reader.metadata or {}
    result = {"basic_info": {"Pages": len(reader.pages), "Encrypted": encrypted, "File Size": f"{Path(path).stat().st_size / 1024:.2f} KB"},
              "metadata": {label: str(metadata.get(key, "N/A"))[:1000] for label, key in (("Title", "/Title"), ("Author", "/Author"), ("Creator", "/Creator"), ("Producer", "/Producer"), ("Creation Date", "/CreationDate"))},
              "security_analysis": [], "risks": [], "javascript": [], "actions": [], "status": "completed"}
    visited, visited_ids = set(), set()
    nodes = 0
    truncated = False
    def walk(obj, location, depth=0):
        nonlocal nodes, truncated
        if depth > 30 or nodes >= 20000:
            truncated = True
            return
        if isinstance(obj, IndirectObject):
            identity = (obj.idnum, obj.generation)
            if identity in visited:
                return
            visited.add(identity)
            obj = obj.get_object()
        if not isinstance(obj, (DictionaryObject, ArrayObject)):
            return
        if id(obj) in visited_ids:
            return
        visited_ids.add(id(obj))
        nodes += 1
        if isinstance(obj, DictionaryObject):
            if "/JS" in obj or obj.get("/S") == "/JavaScript":
                result["javascript"].append("JavaScript action at " + location[:200] + " (not executed)")
            action = obj.get("/S")
            if action == "/URI":
                result["actions"].append("External URI at " + location[:100] + ": " + str(obj.get("/URI", ""))[:1200])
            elif action in {"/Launch", "/GoToR", "/SubmitForm", "/ImportData"}:
                result["actions"].append(str(action) + " action at " + location[:200])
                if action == "/Launch":
                    result["risks"].append("PDF contains a Launch action. No referenced program was executed.")
            if "/EmbeddedFiles" in obj or obj.get("/Subtype") == "/FileAttachment":
                result["security_analysis"].append("Embedded attachment referenced at " + location[:200])
            if "/AcroForm" in obj:
                result["security_analysis"].append("Document contains an AcroForm.")
            for key, child in obj.items():
                # Do not expand page contents, image/font streams, or decompress arbitrary data.
                if str(key) not in {"/Parent", "/Contents", "/Resources", "/Length"}:
                    walk(child, location + str(key), depth + 1)
        else:
            for i, child in enumerate(obj):
                walk(child, location + f"[{i}]", depth + 1)
    walk(reader.root_object, "Catalog")
    if result["javascript"]:
        result["security_analysis"].append("JavaScript actions are present; source was not executed.")
        result["risks"].append("Active JavaScript content requires review; presence alone does not prove maliciousness.")
    if result["actions"]:
        result["security_analysis"].append("Document references interactive actions or external URIs; destinations were not fetched.")
    if truncated:
        result["status"] = "partial"
    for field in ("security_analysis", "risks", "javascript", "actions"):
        result[field] = list(dict.fromkeys(result[field]))[:200]
    result["limitations"] = ["Static PDF object inspection only. Not AI analysis or a malware verdict. No scripts/actions executed or links fetched."] + (["Object traversal limit reached; analysis is partial."] if truncated else [])
    return result


if __name__ == "__main__":
    try:
        # Parent enforces wall time. Unix worker also bounds CPU; Linux bounds address space.
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (12, 14))
            if sys.platform.startswith('linux'):
                resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        except (ImportError, OSError, ValueError):
            pass
        analysis = inspect_apk(sys.argv[2]) if sys.argv[1] == "apk" else inspect_pdf(sys.argv[2])
        print(json.dumps(analysis))
    except ImportError:
        print(json.dumps({"error": "File-analysis dependency unavailable. Install requirements.txt.", "code": "dependency_unavailable"}))
        sys.exit(2)
    except Exception:
        print(json.dumps({"error": "File is invalid, corrupted, unsupported, or exceeds inspection limits.", "code": "invalid_file"}))
        sys.exit(1)
