#!/usr/bin/env python3
"""APK Signal static analyzer.

Static analysis only: the app is never executed and no network request is made.
Report records are tiered (package_fact / static_indicator / static_trace_step /
runtime_observation). This version emits no static traces and no runtime
observations. See coverage.not_modeled in the report for what is not analyzed.

    python apkanalyze.py sample.apkm --json report.json
    python apkanalyze.py --validate report.json
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ANALYZER_VERSION = "0.8.0"
SCHEMA_VERSION = "2.1"
SDK_CATALOG_VERSION = "min-2026.10"

MB = 1024 * 1024
DEFAULT_MAX_TOTAL_MB = 2048
MAX_ENTRIES = 50000
MAX_ENTRY_MB = 512
MAX_STRING_LEN = 4096
MAX_SITES_PER_BEHAVIOR = 50
MAX_XREFS_PER_STRING = 20

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

URL_RE = re.compile(r"(?:https?|wss?)://[^\x00-\x20\"'<>\\]+", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
HOSTPORT_RE = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}):(\d{1,5})$")
DOMAIN_LITERAL_RE = re.compile(
    r"^(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d+)?(?:/[^\s?#]*)?(?:\?[^\s#]*)?(?:#\S*)?$",
    re.IGNORECASE,
)

NON_DOMAIN_SUFFIXES = {
    "apk", "arsc", "class", "csv", "dat", "db", "dex", "dtd", "html", "idx", "java", "json", "kt",
    "list", "map", "mf", "mp3", "mp4", "otf", "pb", "png", "properties", "proto", "jpg", "rsa", "sf",
    "so", "svg", "text", "ttf", "txt", "wav", "webp", "xml", "xsd",
}
KNOWN_TLDS = set(
    "com org net edu gov mil int io dev app ai co info biz xyz cloud me tv uk de fr jp in au ca us ch nl "
    "se no fi es it br ru cn tw kr sg id nz za mx eu tech shop site online store live news work zone team "
    "link host help world systems network agency mobi name coop museum travel pro asia arpa google amazon "
    "microsoft apple bank insurance jobs cat aero post xxx tel onion".split()
)
CODE_PACKAGE_ROOTS = {
    "java", "javax", "kotlin", "kotlinx", "android", "androidx", "dalvik", "jdk", "sun", "libcore",
    "okhttp3", "okio", "retrofit2",
}

SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rebrand.ly", "buff.ly", "shorturl.at"}
TUNNEL_DDNS = (
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "duckdns.org", "no-ip.com",
    "no-ip.org", "no-ip.biz", "ddns.net", "hopto.org", "zapto.org", "servehttp.com", "dyndns.org", "dynu.net",
    "localtunnel.me", "loca.lt",
)
CLOUD_ENDPOINT_SUFFIXES = (
    "firebaseio.com", "firebasestorage.googleapis.com", "storage.googleapis.com", "s3.amazonaws.com",
    "blob.core.windows.net",
)
HIGHLIGHT_FLAGS = {
    "cleartext_http", "cleartext_websocket", "raw_ip", "private_or_local_ip", "userinfo_in_url",
    "messaging_webhook_or_bot_api", "tunnel_or_dynamic_dns", "onion_service",
}

# Versioned, editable attribution catalog (class-name prefixes). Matching a prefix shows where a
# string is referenced from; it does not show who authored the code or the destination.
SDK_CATALOG = (
    ("Lcom/google/android/gms/", "Google Play services"),
    ("Lcom/google/firebase/", "Firebase"),
    ("Lcom/google/android/datatransport/", "Google DataTransport"),
    ("Lcom/google/ads/", "Google Ads"),
    ("Lcom/facebook/", "Facebook SDK"),
    ("Lcom/appsflyer/", "AppsFlyer"),
    ("Lcom/adjust/", "Adjust"),
    ("Lcom/onesignal/", "OneSignal"),
    ("Lcom/unity3d/", "Unity"),
    ("Lio/sentry/", "Sentry"),
    ("Lcom/bugsnag/", "Bugsnag"),
    ("Lcom/mixpanel/", "Mixpanel"),
    ("Lcom/amplitude/", "Amplitude"),
    ("Lcom/android/volley/", "Volley"),
    ("Lokhttp3/", "OkHttp"),
    ("Lretrofit2/", "Retrofit"),
    ("Lcom/squareup/", "Square libraries"),
    ("Landroidx/", "AndroidX"),
    ("Lkotlin/", "Kotlin standard library"),
)

BEHAVIOR_REFLECTION = "Reflection use"
BEHAVIOR_DYNAMIC_LOAD = "Dynamic code loading"
BEHAVIOR_NATIVE_LOAD = "Native library loading"

BEHAVIOR_API_HINTS = {
    "Location access": ("LocationManager;->", "FusedLocationProviderClient", "requestLocationUpdates", "getLastKnownLocation"),
    "Contacts access": ("ContactsContract", "content://com.android.contacts"),
    "SMS access or sending": ("Telephony.Sms", "SmsManager;->", "content://sms"),
    "Call history access": ("CallLog.Calls", "content://call_log"),
    "Camera or microphone access": ("android/hardware/Camera", "CameraManager;->", "MediaRecorder;->", "AudioRecord;->"),
    "Clipboard access": ("ClipboardManager;->", "getPrimaryClip"),
    "File or media access": ("FileInputStream;->", "openFileInput", "MediaStore", "getExternalStorageDirectory"),
    "Device identifier access": ("getImei", "getMeid", "getDeviceId", "ANDROID_ID", "getSubscriberId"),
    "Accessibility service use": ("AccessibilityService", "performGlobalAction", "getRootInActiveWindow"),
    "Device administrator use": ("DeviceAdminReceiver", "DevicePolicyManager;->"),
    "Boot or background persistence": ("BOOT_COMPLETED", "WorkManager", "JobScheduler;->", "startForeground"),
    "WebView use": ("WebView;->loadUrl", "addJavascriptInterface"),
    "Cryptography use": ("javax/crypto/", "java/security/MessageDigest", "Cipher;->"),
    "Network communication": (
        "URL;->openConnection", "HttpURLConnection;->connect", "HttpURLConnection;->getInputStream",
        "Socket;-><init>", "OkHttpClient;->newCall", "RealCall;->execute", "RealCall;->enqueue",
        "Call;->execute", "Call;->enqueue", "HttpClient;->execute", "addToRequestQueue", "WebView;->loadUrl",
    ),
    "Credential or account handling": ("getPassword", "password", "access_token", "refresh_token", "Authorization", "AccountManager", "getAccounts"),
    BEHAVIOR_REFLECTION: ("Ljava/lang/reflect/Method;->invoke", "Ljava/lang/Class;->forName", "getDeclaredMethod"),
    BEHAVIOR_DYNAMIC_LOAD: ("DexClassLoader;-><init>", "InMemoryDexClassLoader", "PathClassLoader;-><init>"),
    BEHAVIOR_NATIVE_LOAD: ("System;->loadLibrary", "System;->load(", "Runtime;->loadLibrary"),
    "Process execution": ("Runtime;->exec", "ProcessBuilder;->start"),
}

PERMISSION_GROUPS = {
    "Location": ("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"),
    "Contacts": ("READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"),
    "SMS": ("READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_PHONE_STATE"),
    "Call logs": ("READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS"),
    "Camera": ("CAMERA",),
    "Microphone": ("RECORD_AUDIO",),
    "Files and media": ("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_", "MANAGE_EXTERNAL_STORAGE"),
    "Accounts": ("GET_ACCOUNTS", "USE_CREDENTIALS", "MANAGE_ACCOUNTS"),
    "Network": ("INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE"),
    "Background execution": ("RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE", "WAKE_LOCK"),
    "Accessibility": ("BIND_ACCESSIBILITY_SERVICE",),
    "Device administration": ("BIND_DEVICE_ADMIN",),
}

EMBEDDED_MAGICS = ((b"dex\n", "dex"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip_apk_or_jar"))

TIERS = {"package_fact", "static_indicator", "static_trace_step", "runtime_observation"}
STATUSES = {"literal_only", "referenced_by_code", "reaches_sink_argument", "runtime_observed"}
FORBIDDEN_WORDING = re.compile(r"\b(sends|leaks|steals|exfiltrates|exfiltrated)\b", re.IGNORECASE)

_ANDROGUARD = {"module": None, "analyze": None}


class ArchiveLimitError(Exception):
    """Raised when a package exceeds configured size or entry limits."""


# --------------------------------------------------------------------------- hashing / evidence

def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(MB), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def file_evidence(path, archive_member=None, display_name=None):
    sha, size = sha256_file(path)
    evidence = {"filename": display_name or Path(path).name, "size_bytes": size, "sha256": sha}
    if archive_member is not None:
        evidence["archive_member"] = archive_member
    return evidence


def hash_step(method, source, output):
    return {"method": method, "input_sha256": sha256_text(source), "output_sha256": sha256_text(output)}


def ledger_entry(container, container_sha256, entry_path, locator, extraction_method, raw_value,
                 tier="static_indicator", decode_chain=None):
    raw_hash = sha256_text(raw_value)
    material = json.dumps(
        {"container_sha256": container_sha256, "locator": locator, "raw_value_sha256": raw_hash},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return {
        "id": hashlib.sha256(material.encode("utf-8")).hexdigest(),
        "tier": tier,
        "container": {"name": container, "sha256": container_sha256},
        "entry_path": entry_path,
        "locator": locator,
        "extraction_method": extraction_method,
        "decode_chain": decode_chain or [],
        "raw_value": raw_value,
        "raw_value_sha256": raw_hash,
    }


def record_error(errors, stage, exc):
    errors.append({"stage": stage, "error_type": type(exc).__name__, "detail": str(exc)[:200]})


# --------------------------------------------------------------------------- archive handling

def unsafe_member_name(name):
    parts = name.replace("\\", "/").split("/")
    return name.startswith(("/", "\\")) or ".." in parts or (len(name) > 1 and name[1] == ":")


def check_limits(infos, max_total_bytes):
    if len(infos) > MAX_ENTRIES:
        raise ArchiveLimitError(f"Archive has {len(infos)} entries (limit {MAX_ENTRIES}).")
    total = sum(info.file_size for info in infos)
    if total > max_total_bytes:
        raise ArchiveLimitError(f"Declared uncompressed size {total} exceeds limit {max_total_bytes} (possible zip bomb).")
    for info in infos:
        if info.file_size > MAX_ENTRY_MB * MB:
            raise ArchiveLimitError(f"Entry exceeds {MAX_ENTRY_MB} MB declared size.")
    return total


def trailing_bytes_after_eocd(path):
    size = os.path.getsize(path)
    with open(path, "rb") as stream:
        stream.seek(max(0, size - (65535 + 22)))
        tail = stream.read()
    pos = tail.rfind(b"PK\x05\x06")
    if pos < 0 or len(tail) < pos + 22:
        return None
    comment_len = int.from_bytes(tail[pos + 20:pos + 22], "little")
    return max(len(tail) - (pos + 22 + comment_len), 0)


def sha256_zip_entry(zf, info, cap=256 * MB):
    digest = hashlib.sha256()
    read = 0
    with zf.open(info) as stream:
        for chunk in iter(lambda: stream.read(MB), b""):
            read += len(chunk)
            if read > cap:
                return None
            digest.update(chunk)
    return digest.hexdigest()


def inspect_archive(path, max_total_bytes, detect_embedded=True, hash_entries=False):
    """Return anomalies, embedded payloads, entry summary and optional per-entry hashes."""
    anomalies, embedded, entries = [], [], []
    year_now = datetime.now(timezone.utc).year
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        total = check_limits(infos, max_total_bytes)
        for name, count in sorted(Counter(i.filename for i in infos).items()):
            if count > 1:
                anomalies.append({"type": "duplicate_entry", "entry": name,
                                  "detail": f"{count} entries share this name; tools may disagree on which one is used."})
        for info in infos:
            if info.is_dir():
                continue
            name = info.filename
            if unsafe_member_name(name):
                anomalies.append({"type": "path_traversal_name", "entry": name, "detail": "Entry name contains an absolute path or '..' component."})
            if info.flag_bits & 0x1:
                anomalies.append({"type": "encrypted_entry", "entry": name, "detail": "Entry is flagged as encrypted."})
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                anomalies.append({"type": "unusual_compression_method", "entry": name, "detail": f"Compression method {info.compress_type}."})
            if info.date_time[0] > year_now:
                anomalies.append({"type": "future_timestamp", "entry": name, "detail": "%04d-%02d-%02d" % info.date_time[:3]})
            if info.compress_size and info.file_size > MB and info.file_size / info.compress_size > 250:
                anomalies.append({"type": "high_compression_ratio", "entry": name,
                                  "detail": f"{info.file_size} bytes from {info.compress_size} compressed."})
            if hash_entries:
                entries.append({"path": name, "size_bytes": info.file_size, "crc32": f"{info.CRC:08x}",
                                "modified": "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time,
                                "sha256": sha256_zip_entry(zf, info)})
            if detect_embedded and info.file_size >= 4:
                try:
                    with zf.open(info) as stream:
                        head = stream.read(4)
                except Exception:
                    continue
                kind = next((label for magic, label in EMBEDDED_MAGICS if head.startswith(magic)), None)
                expected = (kind == "dex" and re.fullmatch(r"classes\d*\.dex", name)) or (kind == "elf" and name.startswith("lib/"))
                if kind and not expected:
                    embedded.append({"path": name, "kind": kind, "size_bytes": info.file_size,
                                     "sha256": sha256_zip_entry(zf, info),
                                     "note": "Content signature found outside its usual location; contents were not analyzed."})
    trailing = trailing_bytes_after_eocd(path)
    if trailing:
        anomalies.append({"type": "trailing_data_after_eocd", "entry": None, "detail": f"{trailing} bytes follow the end of the central directory."})
    names = sorted(i.filename for i in infos if not i.is_dir())
    return {
        "entry_count": len(names),
        "declared_uncompressed_bytes": total,
        "anomalies": sorted(anomalies, key=lambda a: (a["type"], a["entry"] or "")),
        "embedded_payloads": sorted(embedded, key=lambda e: e["path"]),
        "entries": sorted(entries, key=lambda e: e["path"]),
    }, names


def detect_format(path):
    with open(path, "rb") as stream:
        if stream.read(2) != b"PK":
            raise ValueError("Not a ZIP-based package (missing PK signature).")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    if "AndroidManifest.xml" in names:
        return "APK"
    if any(n.lower().endswith(".apk") and not n.endswith("/") for n in names):
        return "BUNDLE"
    raise ValueError("ZIP contains neither AndroidManifest.xml nor inner .apk files.")


def copy_capped(zf, info, dest, cap):
    written = 0
    with zf.open(info) as src, open(dest, "wb") as out:
        for chunk in iter(lambda: src.read(MB), b""):
            written += len(chunk)
            if written > cap:
                raise ArchiveLimitError(f"{info.filename} exceeded {cap} bytes while extracting.")
            out.write(chunk)
    return written


def extract_bundle(path, workdir, max_total_bytes):
    """Extract only inner .apk members, to generated filenames (archive paths are never used for writing)."""
    root = Path(workdir)
    members, info_json = [], None
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        check_limits(infos, max_total_bytes)
        budget = max_total_bytes
        for index, info in enumerate(infos):
            if info.is_dir():
                continue
            lower = info.filename.lower()
            if lower.endswith(".apk"):
                dest = root / f"member_{index:04d}.apk"
                budget -= copy_capped(zf, info, dest, min(MAX_ENTRY_MB * MB, max(budget, 0)))
                members.append((info.filename, dest))
            elif Path(info.filename).name.lower() in ("info.json", "manifest.json") and info.file_size < MB and info_json is None:
                try:
                    info_json = json.loads(zf.read(info))
                except Exception:
                    info_json = None
    members.sort(key=lambda m: (Path(m[0]).name.lower() != "base.apk", m[0].lower()))
    return members, info_json


# --------------------------------------------------------------------------- destinations

def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def valid_domain(value):
    value = value.lower().rstrip(".")
    if len(value) > 253 or valid_ip(value):
        return False
    labels = value.split(".")
    if len(labels) < 2 or len(labels) > 6 or not labels[-1].isalpha():
        return False
    # Reverse-DNS zones, reserved names, and dotted SDK/package identifiers are not destination hosts.
    if value.endswith((".arpa", ".invalid", ".test", ".example", ".localhost", ".local", ".internal")):
        return False
    if labels[0] in {"com", "org", "net", "edu", "gov", "mil"} and len(labels) >= 3:
        return False
    if len(labels) >= 3 and labels[-2:] == ["installation", "id"]:
        return False
    if value == "firebaseinstallations.id":
        return False
    if labels[0] == "debug" and "firebase" in labels and "analytics" in labels and labels[-1] == "app":
        return False
    if labels[0] == "google" and len(labels) >= 3 and labels[1] == "c" and labels[2] in {"a", "sender"}:
        return False
    if value in {"cipher.iv", "gcm.n.link", "it.name", "jna.boot.library.name", "oldfile.name", "os.name", "package.name", "response.id", "user.name"}:
        return False
    if len(labels) >= 3 and "ipaddress" in labels and "error" in labels:
        return False
    if labels[0] in CODE_PACKAGE_ROOTS or (len(labels) == 2 and labels[0] in {"com", "org", "net", "edu", "gov"}):
        return False
    if labels[-1] in NON_DOMAIN_SUFFIXES or labels[-1] not in KNOWN_TLDS:
        return False
    return all(1 <= len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels)


def normalize_url(value):
    """Return a cleaned URL literal, or None if it is not a parseable http(s)/ws(s) URL."""
    value = value.strip().rstrip(".,;:)]}")
    if any(ord(ch) < 32 for ch in value):
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https", "ws", "wss"} or not host or not parsed.netloc:
            return None
        if not re.fullmatch(r"[a-zA-Z0-9.-]+|[0-9a-fA-F:]+", host):
            return None
        if not valid_ip(host) and not re.search(r"\.(?:localhost|local|internal|lan|test)$", host, re.IGNORECASE) and not valid_domain(host):
            return None
        return value
    except ValueError:
        return None


def canonical_host(host):
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            return host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return host.lower()


def normalize_destination_url(url):
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return {
        "scheme": parsed.scheme.lower(),
        "host": canonical_host(parsed.hostname or ""),
        "port": port,
        "path": parsed.path or "/",
        "query_keys": sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}),
    }


def host_normalized(host, port=None):
    return {"scheme": None, "host": canonical_host(host), "port": port, "path": None, "query_keys": []}


def display_destination(normalized):
    host = normalized["host"]
    shown = f"[{host}]" if ":" in host else host
    if normalized.get("port"):
        shown += f":{normalized['port']}"
    if normalized.get("scheme"):
        shown = f"{normalized['scheme']}://{shown}{normalized.get('path') or ''}"
    return shown


def extract_candidates(text):
    """Return [(kind, normalized, probe)] for destination literals inside one string."""
    stripped = text.strip()
    hostport = HOSTPORT_RE.fullmatch(stripped)
    if hostport:
        host, port = hostport.group(1), int(hostport.group(2))
        if 1 <= port <= 65535:
            if valid_ip(host):
                return [("ip", host_normalized(host, port), stripped)]
            if valid_domain(host):
                return [("domain", host_normalized(host, port), stripped)]
    found, covered = [], set()
    for match in URL_RE.finditer(text):
        url = normalize_url(match.group(0))
        if url:
            normalized = normalize_destination_url(url)
            found.append(("websocket" if normalized["scheme"] in ("ws", "wss") else "url", normalized, url))
            covered.add(normalized["host"])
    for match in IP_RE.finditer(text):
        ip = match.group(0)
        if valid_ip(ip) and canonical_host(ip) not in covered:
            found.append(("ip", host_normalized(ip), ip))
            covered.add(canonical_host(ip))
    if not found:
        bare = DOMAIN_LITERAL_RE.fullmatch(stripped)
        if bare and valid_domain(bare.group(1)):
            found.append(("domain", host_normalized(bare.group(1).lower()), stripped))
    return found


def decode_attempts(raw):
    """Yield (method, decoded_text, decode_chain) for constant hex/base64/reversed encodings. No key guessing."""
    s = raw.strip()
    if not (16 <= len(s) <= 2048) or re.search(r"\s", s):
        return
    candidates = []
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        candidates.append(("hex", bytes.fromhex(s)))
    if re.fullmatch(r"[A-Za-z0-9+/_=-]+", s):
        std = s.replace("-", "+").replace("_", "/")
        try:
            candidates.append(("base64", base64.b64decode(std + "=" * (-len(std) % 4), validate=True)))
        except (binascii.Error, ValueError):
            pass
    for method, data in candidates:
        if data and all(0x20 <= b < 0x7F for b in data):
            text = data.decode("ascii")
            yield method, text, [hash_step(method, s, text)]
    reversed_text = s[::-1]
    if "://" in reversed_text:
        yield "reversed", reversed_text, [hash_step("reversed", s, reversed_text)]


def destination_flags(kind, normalized, url=None):
    flags = []

    def add(name, why):
        flags.append({"name": name, "rationale": why})

    scheme, host, port = normalized.get("scheme"), normalized["host"], normalized.get("port")
    path = normalized.get("path") or ""
    if scheme == "http":
        add("cleartext_http", "URL literal uses HTTP; the URL layer provides no transport encryption.")
    if scheme == "ws":
        add("cleartext_websocket", "URL literal uses ws://; the URL layer provides no transport encryption.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        add("raw_ip", "Destination literal is an IP address rather than a hostname.")
        if address.is_private or address.is_loopback or address.is_link_local:
            add("private_or_local_ip", "Literal is in a private, loopback, or link-local range.")
    if url and kind in ("url", "websocket"):
        try:
            if urlsplit(url).username is not None:
                add("userinfo_in_url", "URL literal contains a userinfo component (user[:password]@host).")
        except ValueError:
            pass
    if port and port not in (80, 443):
        add("non_default_port", f"Literal specifies port {port}.")
    if host in SHORTENERS:
        add("url_shortener", "Host is a known URL shortener; the final destination is not visible statically.")
    if any(host == s or host.endswith("." + s) for s in TUNNEL_DDNS):
        add("tunnel_or_dynamic_dns", "Host belongs to a tunneling or dynamic-DNS provider; also used legitimately.")
    if host.endswith(".onion"):
        add("onion_service", "Host is a Tor onion address.")
    if (host == "api.telegram.org" and path.startswith("/bot")) or host == "hooks.slack.com" or \
            (host in ("discord.com", "discordapp.com") and "/webhooks/" in path):
        add("messaging_webhook_or_bot_api", "URL pattern of a messaging webhook or bot API; also used legitimately.")
    if host.endswith(CLOUD_ENDPOINT_SUFFIXES) or ".s3." in host:
        add("cloud_storage_or_database_endpoint", "Host pattern of a cloud storage or database service.")
    return flags


def noise_classification(shown, normalized, kind):
    lowered = shown.lower()
    if kind == "ip" and normalized["host"] in ("0.0.0.0", "255.255.255.255"):
        return {"class": "unspecified_or_broadcast_address", "hidden_by_default": True}
    patterns = (
        ("schema_or_namespace", ("w3.org", "xmlsoap.org", "schemas.android.com", "schemas.microsoft.com", "schema.org",
                                 "xmlpull.org", "ns.adobe.com", "purl.org", "opengis.net")),
        ("license_or_documentation", ("apache.org/licenses", "opensource.org/licenses", "creativecommons.org")),
        ("app_store", ("play.google.com/store", "apps.apple.com")),
        ("placeholder", ("example.com", "example.org", "example.net")),
    )
    for category, needles in patterns:
        if any(needle in lowered for needle in needles):
            return {"class": category, "hidden_by_default": True}
    return {"class": "unclassified", "hidden_by_default": False}


def attribute_class(class_name, package):
    if package:
        prefix = "L" + package.replace(".", "/") + "/"
        if class_name.startswith(prefix):
            return {"class": "app_package_prefix", "rule": f"class name starts with {prefix}"}
    for prefix, label in SDK_CATALOG:
        if class_name.startswith(prefix):
            return {"class": "third_party_catalog", "rule": f"catalog {SDK_CATALOG_VERSION}: {prefix} ({label})"}
    return {"class": "unclassified", "rule": "no package-prefix or catalog match (obfuscation can hide origin)"}


def method_signature(method):
    try:
        encoded = method.get_method() if hasattr(method, "get_method") else method
        return f"{encoded.get_class_name()}->{encoded.get_name()}{encoded.get_descriptor()}"
    except Exception:
        return str(method)


def class_name_of(cls):
    name = getattr(cls, "name", None)
    if isinstance(name, str):
        return name
    try:
        return cls.get_name()
    except Exception:
        return str(cls)


def string_xrefs(dx, raw):
    """List of (class, method_sig, offset) that reference this string, or None if the lookup is unavailable."""
    try:
        analysis = dx.strings.get(raw)
    except Exception:
        return None
    if analysis is None:
        return None
    try:
        try:
            refs = list(analysis.get_xref_from(with_offset=True))
        except TypeError:
            refs = list(analysis.get_xref_from())
    except Exception:
        return None
    out = []
    for ref in refs:
        try:
            out.append((class_name_of(ref[0]), method_signature(ref[1]), ref[2] if len(ref) > 2 else None))
        except Exception:
            continue
    return sorted(out, key=lambda r: (r[0], r[1], str(r[2])))


def build_destinations(ctx, string_records, dx, class_dex, ledger):
    dests, string_ledger, xref_cache = {}, {}, {}
    legacy = {"urls": set(), "domains": set(), "ips": set(), "ports": set()}
    stats = Counter()

    def string_entry(dex_file, idx, raw, via, chain):
        key = (dex_file, idx, via)
        if key not in string_ledger:
            locator = {"kind": "dex", "dex_file": dex_file, "string_idx": idx}
            if via:
                locator["decoded_via"] = via
            string_ledger[key] = ledger_entry(
                ctx["container"], ctx["hash"], dex_file, locator,
                "Androguard DEX string table" + (f" + constant {via} decoding" if via else ""),
                raw, tier="static_indicator" if via else "package_fact", decode_chain=chain)
            ledger.append(string_ledger[key])
        return string_ledger[key]

    for dex_file, idx, raw in string_records:
        if len(raw) > MAX_STRING_LEN:
            stats["strings_skipped_too_long"] += 1
            continue
        if len(raw) < 4:
            continue
        found, via, chain = extract_candidates(raw), None, None
        if not found:
            for method, decoded, steps in decode_attempts(raw):
                found = extract_candidates(decoded)
                if found:
                    via, chain = method, steps
                    break
        if not found:
            continue
        if raw not in xref_cache:
            xref_cache[raw] = string_xrefs(dx, raw)
            stats["xref_" + ("unavailable" if xref_cache[raw] is None else "found" if xref_cache[raw] else "none_found")] += 1
        refs = xref_cache[raw]
        state = "unavailable" if refs is None else ("found" if refs else "none_found")
        entry = string_entry(dex_file, idx, raw, via, chain)
        for kind, normalized, probe in found:
            key = json.dumps({"kind": kind, "normalized": normalized}, sort_keys=True, separators=(",", ":"))
            dest = dests.get(key)
            if dest is None:
                shown = display_destination(normalized)
                dest = dests[key] = {
                    "id": sha256_text(key), "kind": kind, "normalized": normalized, "display": shown,
                    "raw_evidence_ids": [], "occurrences": [],
                    "indicators": destination_flags(kind, normalized, probe),
                    "noise": noise_classification(shown, normalized, kind),
                }
            dest["raw_evidence_ids"].append(entry["id"])
            dest["occurrences"].append({
                "ledger_id": entry["id"], "container": ctx["container"], "component": ctx["component"],
                "locator_kind": "dex_string_decoded" if via else "dex_string", "decoded_via": via,
                "dex_file": dex_file, "string_idx": idx, "xref_state": state,
            })
            for cls, msig, offset in (refs or [])[:MAX_XREFS_PER_STRING]:
                xloc = {"kind": "dex_code", "dex_file": class_dex.get(cls), "class": cls, "method_sig": msig, "xref_offset": offset}
                xentry = ledger_entry(ctx["container"], ctx["hash"], class_dex.get(cls) or "DEX code", xloc,
                                      "Androguard StringAnalysis xref (method references this string)", raw, tier="package_fact")
                ledger.append(xentry)
                dest["raw_evidence_ids"].append(xentry["id"])
                dest["occurrences"].append({
                    "ledger_id": xentry["id"], "container": ctx["container"], "component": ctx["component"],
                    "locator_kind": "dex_code_xref", "dex_file": class_dex.get(cls), "class": cls, "method_sig": msig,
                    "reference_total": len(refs), "attribution": attribute_class(cls, ctx["package"]),
                })
            if kind in ("url", "websocket"):
                legacy["urls"].add(probe)
                (legacy["ips"] if valid_ip(normalized["host"]) else legacy["domains"]).add(normalized["host"])
            elif kind == "ip":
                legacy["ips"].add(normalized["host"])
            else:
                legacy["domains"].add(normalized["host"])
            if normalized.get("port"):
                legacy["ports"].add(normalized["port"])
    return list(dests.values()), legacy, stats


def finalize_destination(dest):
    seen, occurrences = set(), []
    for occ in dest["occurrences"]:
        key = (occ["locator_kind"], occ["container"], occ["ledger_id"])
        if key not in seen:
            seen.add(key)
            occurrences.append(occ)
    dest["occurrences"] = sorted(occurrences, key=lambda o: (o["locator_kind"], o["container"], o["ledger_id"]))
    dest["raw_evidence_ids"] = sorted(set(dest["raw_evidence_ids"]))
    xrefs = [o for o in dest["occurrences"] if o["locator_kind"] == "dex_code_xref"]
    states = {o["xref_state"] for o in dest["occurrences"] if "xref_state" in o}
    dest["observation_status"] = "referenced_by_code" if xrefs else "literal_only"
    dest["xref_state"] = "found" if xrefs else ("unavailable" if "unavailable" in states else "none_found")
    if xrefs:
        dest["unknowns"] = [
            "A method references this literal; this does not show the method runs or is reachable.",
            "No trace was performed, so there is no evidence the value reaches a network call argument.",
            "Runtime contact was not observed.",
        ]
    else:
        dest["unknowns"] = [
            "No evidence this value is used by executed code.",
            "The value could be dead code, a third-party SDK default, documentation, or a schema/namespace URI.",
        ]
        if dest["xref_state"] == "unavailable":
            dest["unknowns"].append("The code-reference lookup was unavailable for this string; absence of references is not evidence of non-use.")
    kinds = {o["attribution"]["class"] for o in xrefs}
    if not xrefs:
        dest["attribution"] = {"class": "unknown", "rules": ["No code references recorded."]}
    else:
        if "app_package_prefix" in kinds:
            cls = "app_package_prefix"
        elif kinds == {"third_party_catalog"}:
            cls = "third_party_catalog"
        else:
            cls = "unclassified"
        dest["attribution"] = {"class": cls, "rules": sorted({o["attribution"]["rule"] for o in xrefs})[:5]}
    return dest


def merge_destinations(components):
    merged = {}
    for component in components:
        for dest in component.get("_destinations", []):
            current = merged.get(dest["id"])
            if current is None:
                merged[dest["id"]] = dest
            else:
                current["raw_evidence_ids"] += dest["raw_evidence_ids"]
                current["occurrences"] += dest["occurrences"]
    return sorted((finalize_destination(d) for d in merged.values()), key=lambda d: d["id"])


def build_hosts(destinations):
    hosts = {}
    for dest in destinations:
        entry = hosts.setdefault(dest["normalized"]["host"], {"host": dest["normalized"]["host"], "destination_count": 0,
                                                             "statuses": set(), "noise_hidden": True, "flags": set()})
        entry["destination_count"] += 1
        entry["statuses"].add(dest["observation_status"])
        entry["noise_hidden"] = entry["noise_hidden"] and dest["noise"]["hidden_by_default"]
        entry["flags"].update(f["name"] for f in dest["indicators"])
    return [{**e, "statuses": sorted(e["statuses"]), "flags": sorted(e["flags"])} for _, e in sorted(hosts.items())]


# --------------------------------------------------------------------------- code scan

def instruction_parts(ins):
    parts = []
    for getter in ("get_name", "get_output", "get_length"):
        try:
            parts.append(getattr(ins, getter)())
        except Exception:
            parts.append("" if getter != "get_length" else 0)
    return tuple(parts)


def scan_methods(dex_list, dex_names, errors):
    """One pass over all methods: coverage counts plus behavior-marker call sites with offsets."""
    stats = Counter()
    markers = {b: [(m, m.lower()) for m in ms] for b, ms in BEHAVIOR_API_HINTS.items()}
    matches = {b: {"markers": set(), "methods": set(), "sites": [], "site_total": 0, "kinds": set()} for b in BEHAVIOR_API_HINTS}
    class_dex = {}
    for dex_idx, dex in enumerate(dex_list):
        dex_name = dex_names[dex_idx]
        try:
            for cls in dex.get_classes():
                class_dex[cls.get_name()] = dex_name
            try:
                methods = list(dex.get_encoded_methods())
            except AttributeError:
                methods = [method for cls in dex.get_classes() for method in cls.get_methods()]
        except Exception as exc:
            stats["dex_files_failed"] += 1
            record_error(errors, f"scan {dex_name}", exc)
            continue
        stats["dex_files_parsed"] += 1
        for method in methods:
            stats["methods_total"] += 1
            try:
                code = method.get_code()
                if not code:
                    flags = method.get_access_flags()
                    if flags & 0x100:
                        stats["jni_native_methods_declared"] += 1
                    if flags & 0x500:
                        stats["methods_native_or_abstract"] += 1
                    continue
                stats["methods_with_code"] += 1
                parts = [instruction_parts(i) for i in code.get_bc().get_instructions()]
                lowered = [f"{name} {out}".lower() for name, out, _ in parts]
                body = "\n".join(lowered)
                sig = method_signature(method)
                for behavior, pairs in markers.items():
                    present = [(orig, low) for orig, low in pairs if low in body]
                    if not present:
                        continue
                    entry = matches[behavior]
                    entry["methods"].add(sig)
                    offset_bytes = 0
                    for index, ((name, out, length), text) in enumerate(zip(parts, lowered)):
                        hit = [orig for orig, low in present if low in text]
                        if hit:
                            kind = "api_reference" if name.startswith("invoke") else "string_literal" if name.startswith("const-string") else "other_reference"
                            entry["site_total"] += 1
                            entry["markers"].update(hit)
                            entry["kinds"].add(kind)
                            if len(entry["sites"]) < MAX_SITES_PER_BEHAVIOR:
                                entry["sites"].append({
                                    "dex_file": dex_name, "class": method.get_class_name(), "method_sig": sig,
                                    "offset_units": offset_bytes // 2, "instruction_index": index,
                                    "opcode": name, "marker": hit[0], "kind": kind, "text": f"{name} {out}".strip(),
                                })
                        offset_bytes += length
            except Exception as exc:
                stats["methods_failed"] += 1
                if stats["methods_failed"] <= 5:
                    record_error(errors, f"method in {dex_name}", exc)
    return stats, matches, class_dex


def behavior_indicators(matches, ctx, ledger):
    indicators = []
    for behavior, value in matches.items():
        if not value["methods"]:
            continue
        ids = []
        for site in value["sites"]:
            locator = {"kind": "dex_code", "dex_file": site["dex_file"], "class": site["class"],
                       "method_sig": site["method_sig"], "code_offset_units": site["offset_units"],
                       "instruction_index": site["instruction_index"]}
            entry = ledger_entry(ctx["container"], ctx["hash"], site["dex_file"], locator,
                                 "Instruction text match against static behavior marker", site["text"])
            ledger.append(entry)
            ids.append(entry["id"])
        indicators.append({
            "behavior": behavior,
            "evidence": sorted(value["markers"])[:5],
            "methods": sorted(value["methods"])[:10],
            "method_count": len(value["methods"]),
            "match_kinds": sorted(value["kinds"]),
            "strength": "api_reference" if "api_reference" in value["kinds"] else "string_or_other_only",
            "site_count": value["site_total"],
            "sites_recorded": len(ids),
            "evidence_ledger_ids": sorted(set(ids)),
        })
    return indicators


# --------------------------------------------------------------------------- manifest / signing

def manifest_info(apk):
    flags, components = {}, {"activities": [], "services": [], "receivers": [], "providers": []}
    try:
        app = apk.get_android_manifest_xml().find("application")
        if app is not None:
            for attr in ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig", "extractNativeLibs"):
                value = app.get(ANDROID_NS + attr)
                if value is not None:
                    flags[attr] = value
            tag_map = {"activity": "activities", "activity-alias": "activities", "service": "services",
                       "receiver": "receivers", "provider": "providers"}
            for node in list(app):
                category = tag_map.get(str(node.tag).split("}")[-1])
                if category:
                    components[category].append({
                        "name": node.get(ANDROID_NS + "name", "Unknown"),
                        "exported": node.get(ANDROID_NS + "exported"),
                        "permission": node.get(ANDROID_NS + "permission"),
                        "has_intent_filter": bool(node.findall("intent-filter")),
                    })
    except Exception as exc:
        flags["_error"] = type(exc).__name__
    return flags, components


def parse_network_security_config(apk, names):
    path = "res/xml/network_security_config.xml"
    if path not in names:
        return {"status": "not_found_at_default_path", "note": "Resource shrinking can rename this file; absence here is not proof of no config."}
    try:
        from androguard.core.axml import AXMLPrinter
        root = AXMLPrinter(apk.get_file(path)).get_xml_obj()

        def attr(node, name):
            return node.get(name) if node.get(name) is not None else node.get(ANDROID_NS + name)

        domains = []
        for config in root.iter("domain-config"):
            pins = len(list(config.iter("pin")))
            for domain in config.findall("domain"):
                domains.append({"domain": (domain.text or "").strip(), "include_subdomains": attr(domain, "includeSubdomains"),
                                "cleartext_permitted": attr(config, "cleartextTrafficPermitted"), "pin_count": pins})
        base = root.find("base-config")
        return {"status": "parsed", "path": path, "domain_configs": sorted(domains, key=lambda d: d["domain"]),
                "base_cleartext_permitted": attr(base, "cleartextTrafficPermitted") if base is not None else None}
    except Exception as exc:
        return {"status": "parse_failed", "error_type": type(exc).__name__}


def signing_info(apk):
    info = {"schemes": {}, "certificates": [], "errors": []}
    for key, fn in (("v1", "is_signed_v1"), ("v2", "is_signed_v2"), ("v3", "is_signed_v3")):
        try:
            info["schemes"][key] = bool(getattr(apk, fn)())
        except Exception as exc:
            info["schemes"][key] = None
            info["errors"].append(f"{fn}: {type(exc).__name__}")
    try:
        for cert in apk.get_certificates():
            item = {"sha256": hashlib.sha256(cert.dump()).hexdigest()}
            for field, getter in (("subject", lambda c: c.subject.human_friendly), ("issuer", lambda c: c.issuer.human_friendly)):
                try:
                    item[field] = getter(cert)
                except Exception:
                    item[field] = None
            info["certificates"].append(item)
        info["certificates"].sort(key=lambda c: c["sha256"])
    except Exception as exc:
        info["errors"].append(f"get_certificates: {type(exc).__name__}")
    return info


def analyze_behavior(apk, native_libraries, indicators):
    permissions = sorted(set(apk.get_permissions()))
    groups = [{"category": c, "permissions": [p for p in permissions if any(m in p for m in marks)]}
              for c, marks in PERMISSION_GROUPS.items()]
    _, components = manifest_info(apk)
    return {
        "analysis_type": "static_inference",
        "runtime_observed": False,
        "permission_groups": [g for g in groups if g["permissions"]],
        "requested_permissions": permissions,
        "components": components,
        "api_indicators": indicators,
        "native_libraries": native_libraries,
        "note": "Inferred from manifest declarations and code references. These indicators do not prove the behavior occurs at runtime.",
    }


# --------------------------------------------------------------------------- per-package analysis

def get_analyzer():
    if _ANDROGUARD["analyze"] is None:
        try:
            from loguru import logger

            logger.remove()
            logger.add(sys.stderr, level="WARNING")
            import androguard
            from androguard.misc import AnalyzeAPK
        except ImportError:
            raise SystemExit("androguard and loguru are required: pip install -r requirements.txt")
        _ANDROGUARD["module"], _ANDROGUARD["analyze"] = androguard, AnalyzeAPK
    return _ANDROGUARD["analyze"]


def androguard_version():
    return getattr(_ANDROGUARD["module"], "__version__", "unknown")


def dex_names_for(apk, count):
    try:
        names = list(apk.get_dex_names())
        if len(names) == count:
            key = lambda n: int(re.sub(r"\D", "", n) or 1)
            return sorted(names, key=key), "APK.get_dex_names"
    except Exception:
        pass
    return ["classes.dex" if i == 0 else f"classes{i + 1}.dex" for i in range(count)], "ordinal_position"


def analyze_apk(apk_path, max_total_bytes, component=None, archive_member=None, hash_entries=False):
    analyze = get_analyzer()
    print(f"[*] Loading APK{f' component {component}' if component else ''}...", file=sys.stderr)
    errors = []
    evidence = file_evidence(apk_path, archive_member, Path(archive_member).name if archive_member else None)
    container = evidence.get("archive_member") or evidence["filename"]
    ctx = {"container": container, "hash": evidence["sha256"], "component": component or container}

    try:
        archive, names = inspect_archive(apk_path, max_total_bytes, detect_embedded=True, hash_entries=hash_entries)
    except ArchiveLimitError:
        raise
    except Exception as exc:
        record_error(errors, "archive inspection", exc)
        archive, names = {"entry_count": 0, "declared_uncompressed_bytes": 0, "anomalies": [], "embedded_payloads": [], "entries": []}, []

    apk, dex_list, dx = analyze(apk_path)
    dex_list = list(dex_list) if isinstance(dex_list, (list, tuple)) else [dex_list]
    package = apk.get_package()
    ctx["package"] = package
    print(f"[+] Package: {package}", file=sys.stderr)
    dex_names, dex_basis = dex_names_for(apk, len(dex_list))

    ledger = []
    manifest_permissions = sorted(set(apk.get_permissions()))
    for permission in manifest_permissions:
        locator = {"kind": "manifest", "path": f"/manifest/uses-permission[@android:name='{permission}']", "attribute": "android:name"}
        ledger.append(ledger_entry(container, evidence["sha256"], "AndroidManifest.xml", locator,
                                   "Androguard decoded manifest permission", permission, tier="package_fact"))

    string_records = []
    for index, dex in enumerate(dex_list):
        try:
            string_records += [(dex_names[index], i, str(v)) for i, v in enumerate(dex.get_strings())]
        except Exception as exc:
            record_error(errors, f"strings {dex_names[index]}", exc)

    stats, matches, class_dex = scan_methods(dex_list, dex_names, errors)
    destinations, legacy, dest_stats = build_destinations(ctx, string_records, dx, class_dex, ledger)
    indicators = behavior_indicators(matches, ctx, ledger)
    native_libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    manifest_flags, _ = manifest_info(apk)

    urls, ips = sorted(legacy["urls"]), sorted(legacy["ips"])
    site_counts = {b: matches[b]["site_total"] for b in (BEHAVIOR_REFLECTION, BEHAVIOR_DYNAMIC_LOAD, BEHAVIOR_NATIVE_LOAD)}
    result = {
        "apk": Path(apk_path).name if component is None else None,
        "evidence": evidence,
        "package": package,
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "network_indicators": {"urls": urls, "domains": sorted(legacy["domains"]), "ip_addresses": ips, "ports": sorted(legacy["ports"])},
        "endpoint_analysis": [{"endpoint": u, "indicators": classify_endpoint(u)} for u in urls],
        "data_flow_findings": [],
        "data_flow_analysis_status": {
            "status": "not_performed",
            "reason": "No register-level or interprocedural source-to-sink tracing is implemented; static co-occurrence is deliberately not reported as a data flow.",
        },
        "coverage": {
            "dex_files_parsed": stats["dex_files_parsed"], "dex_files_failed": stats["dex_files_failed"],
            "methods_total": stats["methods_total"], "methods_with_code": stats["methods_with_code"],
            "methods_native_or_abstract": stats["methods_native_or_abstract"],
            "methods_failed": stats["methods_failed"],
            "jni_native_methods_declared": stats["jni_native_methods_declared"],
            "strings_scanned": len(string_records), "strings_skipped_too_long": dest_stats["strings_skipped_too_long"],
            "reflection_sites_detected": site_counts[BEHAVIOR_REFLECTION],
            "dynamic_load_sites_detected": site_counts[BEHAVIOR_DYNAMIC_LOAD],
            "native_load_sites_detected": site_counts[BEHAVIOR_NATIVE_LOAD],
            "string_xref_lookups": {k: dest_stats["xref_" + k] for k in ("found", "none_found", "unavailable")},
            "dex_name_basis": dex_basis,
        },
        "behavior_analysis": analyze_behavior(apk, native_libs, indicators),
        "manifest_flags": manifest_flags,
        "network_security_config": parse_network_security_config(apk, set(names)),
        "signing": signing_info(apk),
        "archive": archive,
        "errors": errors,
    }
    if component:
        result["component"] = component
    result["_evidence_ledger"] = ledger
    result["_destinations"] = destinations
    return result


def classify_endpoint(endpoint):
    lowered = endpoint.lower()
    found = []
    if lowered.startswith("http://"):
        found.append("PLAINTEXT_HTTP")
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", lowered):
        found.append("DIRECT_IP")
    for term in ("upload", "collect", "telemetry", "track", "analytics", "config", "command", "execute", "callback", "beacon"):
        if term in lowered:
            found.append(f"PATH_CONTAINS_{term.upper()}")
    return found


# --------------------------------------------------------------------------- report assembly

def build_coverage(components):
    def total(key):
        return sum(c.get("coverage", {}).get(key, 0) for c in components)

    return {
        "data_flow_analysis_status": "not_performed",
        "reason": "The register-level source-to-sink trace engine is not implemented. Same-method and same-class co-occurrence are not treated as traces.",
        "counts": {
            "components_analyzed": len(components),
            "dex_files_parsed": total("dex_files_parsed"), "dex_files_failed": total("dex_files_failed"),
            "methods_total": total("methods_total"),
            "methods_scanned_for_static_api_hints": total("methods_with_code"),
            "methods_without_code_or_skipped": max(0, total("methods_total") - total("methods_with_code")),
            "methods_native_or_abstract": total("methods_native_or_abstract"),
            "methods_failed": total("methods_failed"),
            "jni_native_methods_declared": total("jni_native_methods_declared"),
            "invokes_resolved": 0, "invokes_unresolved": 0, "invokes_ambiguous": 0,
            "reflection_sites_modeled": 0, "jni_sites_modeled": 0, "dynamic_load_sites_modeled": 0,
            "reflection_sites_detected": total("reflection_sites_detected"),
            "dynamic_load_sites_detected": total("dynamic_load_sites_detected"),
            "native_load_sites_detected": total("native_load_sites_detected"),
            "strings_scanned": total("strings_scanned"),
            "static_traces": 0,
        },
        "not_modeled": [
            "Register-level and interprocedural taint propagation.",
            "Call graph reachability and callback or thread boundaries.",
            "Reflection, JNI, dynamically loaded code, and native control flow (sites are counted, not followed).",
            "Runtime DNS, connections, requests, responses, and payload contents.",
            "Decoded constants beyond whole-string hex, base64, and reversed encodings.",
        ],
        "negative_result_statement": "No traces found within the modeled coverage above. This does not show the app does not transmit data.",
    }


def build_triage_summary(components, destinations):
    visible = [d for d in destinations if not d["noise"]["hidden_by_default"]]
    highlights = sorted((
        {"destination_id": d["id"], "display": d["display"], "observation_status": d["observation_status"],
         "flags": sorted(f["name"] for f in d["indicators"] if f["name"] in HIGHLIGHT_FLAGS),
         "evidence_ledger_ids": d["raw_evidence_ids"][:3]}
        for d in visible if any(f["name"] in HIGHLIGHT_FLAGS for f in d["indicators"])
    ), key=lambda h: h["display"])[:50]
    behaviors = sorted({h["behavior"] for c in components for h in c["behavior_analysis"]["api_indicators"]})
    return {
        "assessment": "Static package indicators only. This report contains no runtime observations and does not establish execution or transmission.",
        "package_names": sorted({c["package"] for c in components if c.get("package")}),
        "component_count": len(components),
        "destination_count": len(destinations),
        "destinations_hidden_as_noise": len(destinations) - len(visible),
        "destinations_by_status": dict(sorted(Counter(d["observation_status"] for d in destinations).items())),
        "indicator_flag_counts": dict(sorted(Counter(f["name"] for d in visible for f in d["indicators"]).items())),
        "static_url_literal_count": len({u for c in components for u in c["network_indicators"]["urls"]}),
        "static_domain_literal_count": len({u for c in components for u in c["network_indicators"]["domains"]}),
        "static_ip_literal_count": len({u for c in components for u in c["network_indicators"]["ip_addresses"]}),
        "requested_permission_count": len({p for c in components for p in c["behavior_analysis"]["requested_permissions"]}),
        "code_behavior_hint_count": len(behaviors),
        "embedded_payload_count": sum(len(c["archive"]["embedded_payloads"]) for c in components),
        "archive_anomaly_count": sum(len(c["archive"]["anomalies"]) for c in components),
        "highlighted_destinations": highlights,
        "not_established": [
            "Whether any listed URL, domain, or IP is contacted at runtime.",
            "Whether any personal or sensitive data is transmitted.",
            "The destination and contents of actual network requests.",
            "The behavior of dynamically loaded code or server-provided configuration.",
        ],
        "next_evidence_needed": [
            "Instrumented execution with timestamped DNS, connection, TLS, and HTTP request/response capture.",
            "Correlate captured destinations and payload fields with an identified app process and action.",
            "Preserve the original sample and capture artifacts with hashes and examiner notes.",
        ],
    }


def build_functionality_summary(components, destinations, bundle):
    """Create a portable, evidence-linked functionality estimate from static report data."""
    package_names = sorted({c.get("package") for c in components if c.get("package")})
    versions = sorted({str(c.get("version_name")) for c in components if c.get("version_name")})
    info = (bundle or {}).get("info_json") or {}
    app_name = info.get("app_name") or info.get("apk_title")
    app_prefixes = set()
    for package in package_names:
        labels = package.split(".")
        app_prefixes.add(package.lower())
        if len(labels) >= 2:
            app_prefixes.add(".".join(labels[:2]).lower())

    component_names = []
    app_component_names = []
    component_names_by_kind = {}
    component_counts = Counter()
    activities = []
    permission_groups = {}
    api_hints = {}
    for component in components:
        behavior = component.get("behavior_analysis") or {}
        for kind, items in (behavior.get("components") or {}).items():
            component_counts[kind] += len(items)
            for item in items:
                name = str(item.get("name") or "")
                if name:
                    component_names.append(name)
                    component_names_by_kind.setdefault(kind, set()).add(name)
                    lowered_name = name.lower()
                    if any(lowered_name == prefix or lowered_name.startswith(prefix + ".") for prefix in app_prefixes):
                        app_component_names.append(name)
                    if kind == "activities":
                        activities.append(name)
        for group in behavior.get("permission_groups", []):
            permissions = permission_groups.setdefault(group.get("category", "Other"), set())
            permissions.update(group.get("permissions", []))
        for hint in behavior.get("api_indicators", []):
            name = hint.get("behavior")
            if name:
                item = api_hints.setdefault(name, {"sites": 0, "methods": set(), "evidence": set()})
                item["sites"] += int(hint.get("site_count", 0))
                item["methods"].update(hint.get("methods", []))
                item["evidence"].update(hint.get("evidence", []))

    component_names = sorted(set(component_names))
    app_component_names = sorted(set(app_component_names))
    # Keep feature inference tied to app-namespace manifest classes where possible.
    feature_names = app_component_names or component_names
    activities = sorted(set(name for name in activities if name in feature_names))
    permissions_flat = sorted({permission for values in permission_groups.values() for permission in values})
    api_names = sorted(api_hints)
    sources = {"manifest_component_name": feature_names}
    feature_rules = [
        ("account and identity", re.compile(r"login|sign.?in|oauth|account|credential|authenticat|identity|profile", re.I)),
        ("messaging and notifications", re.compile(r"messag|chat|conversation|notification|push", re.I)),
        ("media capture or playback", re.compile(r"camera|microphone|audio|video|photo|gallery|recording", re.I)),
        ("location or mapping", re.compile(r"location|geofence|maps?|navigation|gps", re.I)),
        ("file or document handling", re.compile(r"files?|documents?|storage|download|upload|attachment", re.I)),
        ("shopping or payments", re.compile(r"payment|checkout|billing|wallet|cart|purchase|subscription", re.I)),
        ("content browsing or search", re.compile(r"browser|webview|search|feed|article|catalog", re.I)),
        ("health or fitness", re.compile(r"health|fitness|workout|step.?counter", re.I)),
        ("VPN or network tunneling", re.compile(r"vpn|tunnel|warp|tun2socks", re.I)),
        ("DNS or network controls", re.compile(r"dns|connectivity|network communication", re.I)),
        ("device or security management", re.compile(r"device posture|accessibility service|certificate|biometric|security", re.I)),
        ("synchronization or backup", re.compile(r"sync|synchroni[sz]|backup|restore", re.I)),
        ("settings and preferences", re.compile(r"settings|preferences|configuration", re.I)),
        ("support or help", re.compile(r"support|help|feedback", re.I)),
    ]
    functional_areas = []
    for label, pattern in feature_rules:
        evidence = {source: [value for value in values if pattern.search(value)][:8]
                    for source, values in sources.items()}
        evidence = {source: values for source, values in evidence.items() if values}
        if evidence:
            functional_areas.append({"area": label, "evidence_sources": evidence})

    workflow_rules = [
        ("setup_or_onboarding", re.compile(r"onboard|welcome|first.?run|intro", re.I)),
        ("account_or_sign_in", re.compile(r"login|sign.?in|oauth|account|team|organization|profile", re.I)),
        ("main_or_home_screen", re.compile(r"mainactivity|homeactivity|dashboard|homescreen", re.I)),
        ("feature_or_task_screens", re.compile(r"camera|photo|gallery|map|search|chat|message|checkout|payment|vpn|tunnel|dns|document|file", re.I)),
        ("settings_or_configuration", re.compile(r"settings|preferences|configuration", re.I)),
        ("help_or_support", re.compile(r"support|help|feedback", re.I)),
    ]
    workflow_indicators = []
    for stage, pattern in workflow_rules:
        matches = [name for name in activities if pattern.search(name)]
        if matches:
            workflow_indicators.append({"stage": stage, "activity_names": matches[:10]})

    destinations_by_kind = Counter(d.get("kind", "unknown") for d in destinations)
    hosts = sorted({(d.get("normalized") or {}).get("host") for d in destinations if (d.get("normalized") or {}).get("host")})
    status_counts = Counter(d.get("observation_status", "unclassified") for d in destinations)
    cleartext_count = sum(any(flag.get("name") == "cleartext_http" for flag in d.get("indicators", [])) for d in destinations)
    destinations_count = {
        "urls": destinations_by_kind.get("url", 0),
        "websockets": destinations_by_kind.get("websocket", 0),
        "domains": destinations_by_kind.get("domain", 0),
        "ips": destinations_by_kind.get("ip", 0),
        "distinct_hosts": len(hosts),
        "cleartext_http_indicators": cleartext_count,
        "observation_status_counts": dict(sorted(status_counts.items())),
        "sample_hosts": hosts[:10],
    }

    sensitive_pattern = re.compile(r"location|contacts|camera|microphone|clipboard|file or media|device identifier|credential|account|accessibility", re.I)
    sensitive_hints = sorted(name for name in api_hints if sensitive_pattern.search(name))
    identity = ", ".join(package_names) if package_names else "Package identity not recorded"
    if app_name:
        identity = f"{app_name} ({identity}; package metadata name not independently verified)"
    if versions:
        identity += f", version {', '.join(versions)}"
    if functional_areas:
        areas = ", ".join(item["area"] for item in functional_areas[:6])
        narrative = f"Application-namespace manifest components for {identity} indicate screens or services related to {areas}."
    else:
        narrative = f"Static indicators identify {identity}, but application-namespace component names do not support a specific functional description."
    if workflow_indicators:
        narrative += " Manifest activity names provide workflow hints, but do not establish screen order or actual navigation."
    else:
        narrative += " No recognizable activity-name workflow was recovered."

    return {
        "summary_type": "static_functionality_estimate",
        "summary": narrative,
        "identity": {"package_names": package_names, "app_name_from_bundle_metadata": app_name, "version_names": versions},
        "functional_areas": functional_areas,
        "application_component_names": app_component_names[:100],
        "workflow_indicators": workflow_indicators,
        "workflow_order_established": False,
        "manifest_component_counts": dict(sorted(component_counts.items())),
        "manifest_component_name_samples": {kind: sorted(names)[:20] for kind, names in sorted(component_names_by_kind.items())},
        "permission_groups": [{"category": category, "permissions": sorted(values)} for category, values in sorted(permission_groups.items())],
        "api_behavior_hints": [{"behavior": name, "site_count": api_hints[name]["sites"],
                                 "method_count": len(api_hints[name]["methods"]),
                                 "evidence": sorted(api_hints[name]["evidence"])[:8]} for name in api_names],
        "sensitive_data_access_indicators": sensitive_hints,
        "network_surface": destinations_count,
        "runtime_observed": False,
        "source_to_sink_tracing_performed": False,
        "limitations": [
            "Functional areas are inferred from static component names, requested permissions, and API references; they are not proof that a feature executes.",
            "Manifest activity names do not establish actual user navigation or screen order.",
            "Destination literals and code references do not establish runtime contact or data transmission.",
            "The analyzer does not perform register-level or interprocedural sensitive-data source-to-sink tracing.",
        ],
    }


def build_report(results, input_evidence, package_format, claimed_extension, bundle, started, completed):
    ledger = {}
    for r in results:
        for entry in r["_evidence_ledger"]:
            ledger[entry["id"]] = entry
    source = ledger_entry(input_evidence["filename"], input_evidence["sha256"], input_evidence["filename"],
                          {"kind": "raw_file", "byte_offset": None, "length_bytes": input_evidence["size_bytes"]},
                          "SHA-256 file hashing", f"sha256:{input_evidence['sha256']}", tier="package_fact")
    ledger[source["id"]] = source
    destinations = merge_destinations(results)
    clean = []
    for r in results:
        ev = r["evidence"]
        name = ev.get("archive_member") or ev["filename"]
        fact = ledger_entry(name, ev["sha256"], name, {"kind": "raw_file", "byte_offset": None, "length_bytes": ev["size_bytes"]},
                            "SHA-256 file hashing", f"sha256:{ev['sha256']}", tier="package_fact")
        ledger[fact["id"]] = fact
        item = {k: v for k, v in r.items() if not k.startswith("_")}
        item["component_evidence_ledger_id"] = fact["id"]
        item["evidence_ledger_ids"] = sorted({e["id"] for e in r["_evidence_ledger"]} | {fact["id"]})
        clean.append(item)
    all_errors = [{"component": c.get("component") or c["evidence"]["filename"], **e} for c in clean for e in c["errors"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "package_format": package_format,
        "source_evidence": {**input_evidence, "claimed_extension": claimed_extension, "evidence_ledger_id": source["id"]},
        "analysis_metadata": {
            "schema_version": SCHEMA_VERSION,
            "analyzer": "APK Signal static analyzer",
            "analyzer_version": ANALYZER_VERSION,
            "androguard_version": androguard_version(),
            "analyzer_source": file_evidence(Path(__file__)),
            "sdk_catalog_version": SDK_CATALOG_VERSION,
            "analysis_type": "static",
            "runtime_observed": False,
            "offset_notes": "code_offset_units is the cumulative Instruction.get_length() divided by 2 (assumes bytes). xref_offset is passed through from Androguard unchanged.",
            "limitations": [
                "No app execution or network traffic was captured.",
                "Register-level and interprocedural source-to-sink tracing is not performed.",
                "Destination records identify package literals and code references only; they do not establish runtime contact.",
                "Static indicators do not establish execution or transmission.",
                "Obfuscated, encrypted, or runtime-built strings are not recovered.",
            ],
        },
        "run": {"started_utc": started, "completed_utc": completed},
        "bundle": bundle,
        "evidence_ledger": sorted(ledger.values(), key=lambda e: e["id"]),
        "destinations": destinations,
        "hosts": build_hosts(destinations),
        "static_traces": [],
        "runtime_evidence": {"status": "none_imported", "entries": []},
        "coverage": build_coverage(clean),
        "functionality_summary": build_functionality_summary(clean, destinations, bundle),
        "triage_summary": build_triage_summary(clean, destinations),
        "errors": all_errors,
        "analyst_notes": [],
        "components": clean,
    }


# --------------------------------------------------------------------------- validation

def validate_report(report):
    problems = []
    for key in ("schema_version", "source_evidence", "evidence_ledger", "destinations", "static_traces",
                "runtime_evidence", "coverage", "triage_summary", "components"):
        if key not in report:
            problems.append(f"missing top-level key: {key}")
    if problems:
        return problems
    ids = [e["id"] for e in report["evidence_ledger"]]
    if len(ids) != len(set(ids)):
        problems.append("duplicate ledger ids")
    known = set(ids)
    for entry in report["evidence_ledger"]:
        if entry["tier"] not in TIERS:
            problems.append(f"invalid tier on {entry['id'][:12]}")
        if entry["tier"] == "runtime_observation" and not report["runtime_evidence"].get("entries"):
            problems.append(f"runtime_observation entry without imported runtime evidence: {entry['id'][:12]}")
    cited = [report["source_evidence"].get("evidence_ledger_id")]
    for c in report["components"]:
        cited += c.get("evidence_ledger_ids", []) + [c.get("component_evidence_ledger_id")]
        for ind in c.get("behavior_analysis", {}).get("api_indicators", []):
            cited += ind.get("evidence_ledger_ids", [])
    dest_ids = set()
    for d in report["destinations"]:
        if d["id"] in dest_ids:
            problems.append(f"duplicate destination id {d['id'][:12]}")
        dest_ids.add(d["id"])
        cited += d["raw_evidence_ids"] + [o["ledger_id"] for o in d["occurrences"]]
        if d["observation_status"] not in STATUSES:
            problems.append(f"invalid status on destination {d['display']}")
        if d["observation_status"] == "referenced_by_code" and not any(o["locator_kind"] == "dex_code_xref" for o in d["occurrences"]):
            problems.append(f"referenced_by_code without a code reference: {d['display']}")
        if d["observation_status"] in ("reaches_sink_argument", "runtime_observed"):
            problems.append(f"status not supported by this analyzer version: {d['display']}")
    for h in report["triage_summary"].get("highlighted_destinations", []):
        cited += h["evidence_ledger_ids"]
    for ref in cited:
        if ref is not None and ref not in known:
            problems.append(f"cited ledger id not found: {str(ref)[:12]}")
    if report["static_traces"] and report["coverage"].get("data_flow_analysis_status") == "not_performed":
        problems.append("static_traces present although flow analysis is marked not_performed")
    authored = [report["triage_summary"], report.get("functionality_summary", {}), report["coverage"], report["analysis_metadata"],
                [[d["unknowns"], d["indicators"], d["attribution"]] for d in report["destinations"]]]
    if FORBIDDEN_WORDING.search(json.dumps(authored)):
        problems.append("tool-authored text contains a forbidden claim word")
    return problems


# --------------------------------------------------------------------------- CLI

def print_report(result, verbose=False):
    net, cov = result["network_indicators"], result["coverage"]
    print("\n" + "=" * 60)
    print(f" {result['package']}  {result['version_name']} ({result['version_code']})")
    if "component" in result:
        print(f" component: {result['component']}")
    print(f" sha256: {result['evidence']['sha256']}")
    print("=" * 60)
    print(f" URLs {len(net['urls'])}  domains {len(net['domains'])}  IPs {len(net['ip_addresses'])}  ports {len(net['ports'])}")
    print(f" methods {cov['methods_total']}  scanned {cov['methods_with_code']}  failed {cov['methods_failed']}  dex failed {cov['dex_files_failed']}")
    print(f" reflection sites {cov['reflection_sites_detected']}  dynamic-load sites {cov['dynamic_load_sites_detected']}  embedded payloads {len(result['archive']['embedded_payloads'])}")
    shown = net["urls"] if verbose else [u for u in net["urls"] if classify_endpoint(u)][:15]
    for url in shown:
        print(f"   {url}  {classify_endpoint(url)}")
    for ind in result["behavior_analysis"]["api_indicators"]:
        print(f"   behavior: {ind['behavior']} [{ind['strength']}, {ind['method_count']} methods]")
    print(" Flow analysis: not performed (static indicators only)")


def run_validate(path):
    try:
        with open(path, encoding="utf-8") as stream:
            report = json.load(stream)
        problems = validate_report(report)
        if not problems:
            from validate_report import validate_json_schema, validate_references, validate_structural

            ledger_ids = validate_structural(report)
            validate_references(report, ledger_ids)
            mode = validate_json_schema(report, Path(__file__).with_name("report.schema.json"))
        else:
            mode = "internal consistency"
    except Exception as exc:
        problems = [f"{type(exc).__name__}: {exc}"]
        mode = "validation"
    for problem in problems:
        print(f"[!] {problem}")
    print(f"[+] report is consistent ({mode})" if not problems else f"[!] {len(problems)} problem(s)")
    return 1 if problems else 0


def write_report(path, report):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=True, sort_keys=True)
    os.replace(tmp, path)
    digest, _ = sha256_file(path)
    with open(f"{path}.sha256", "w", encoding="utf-8") as stream:
        stream.write(f"{digest}  {Path(path).name}\n")
    return digest


def analyze_path(apk_path, max_size_mb=DEFAULT_MAX_TOTAL_MB, hash_entries=False):
    """Analyze an APK or APKM/XAPK/APKS bundle and return its validated report."""
    path = Path(apk_path)
    if not path.is_file():
        raise FileNotFoundError(f"Package file not found: {path}")
    if max_size_mb <= 0:
        raise ValueError("max_size_mb must be a positive integer")

    limit = max_size_mb * MB
    input_evidence = file_evidence(path)
    started = datetime.now(timezone.utc).isoformat()
    detected = detect_format(path)
    claimed = path.suffix.lower().lstrip(".")
    bundle = None
    if detected == "APK":
        results = [analyze_apk(str(path), limit, hash_entries=hash_entries)]
        package_format = "APK"
    else:
        package_format = claimed.upper() if claimed in ("apkm", "xapk", "apks") else "APKM"
        outer, _ = inspect_archive(path, limit, detect_embedded=False)
        with tempfile.TemporaryDirectory(prefix="apkanalyze_") as workdir:
            members, info_json = extract_bundle(path, workdir, limit)
            results = [
                analyze_apk(str(member_path), limit, component=name, archive_member=name, hash_entries=hash_entries)
                for name, member_path in members
            ]
        signer_sets = [sorted(c["sha256"] for c in result["signing"]["certificates"]) for result in results]
        bundle = {
            "detected_format": "bundle",
            "claimed_extension": claimed,
            "splits": [
                {
                    "archive_member": result["component"],
                    "sha256": result["evidence"]["sha256"],
                    "size_bytes": result["evidence"]["size_bytes"],
                    "package": result["package"],
                }
                for result in results
            ],
            "info_json": info_json,
            "info_json_note": "Metadata supplied inside the package; not verified.",
            "signing_consistency": {
                "all_splits_same_signer": len({tuple(signers) for signers in signer_sets}) <= 1,
                "signer_sha256_sets": signer_sets,
            },
            "archive_anomalies": outer["anomalies"],
        }

    completed = datetime.now(timezone.utc).isoformat()
    if file_evidence(path)["sha256"] != input_evidence["sha256"]:
        raise RuntimeError("Input file changed during analysis; refusing to finalize the report.")

    report = build_report(results, input_evidence, package_format, claimed, bundle, started, completed)
    problems = validate_report(report)
    if problems:
        raise RuntimeError("Internal consistency check failed: " + "; ".join(problems[:3]))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Static APK and APKM analyzer")
    parser.add_argument("apk", nargs="?", help="Path to an APK or APKM/XAPK/APKS bundle")
    parser.add_argument("--json", help="Write the JSON report here (a .sha256 sidecar is written too)")
    parser.add_argument("--validate", metavar="REPORT", help="Check a report for schema and evidence-link consistency")
    parser.add_argument("--max-size-mb", type=int, default=DEFAULT_MAX_TOTAL_MB, help="Total uncompressed size limit")
    parser.add_argument("--hash-entries", action="store_true", help="Include per-entry SHA-256 for every archive entry")
    parser.add_argument("--verbose", action="store_true", help="List every URL on the console")
    args = parser.parse_args(argv)

    if args.validate:
        return run_validate(args.validate)
    if not args.apk:
        parser.error("an APK/APKM path or --validate is required")
    path = Path(args.apk)
    try:
        report = analyze_path(path, args.max_size_mb, args.hash_entries)
        for result in report["components"]:
            print_report(result, args.verbose)
        if args.json:
            digest = write_report(args.json, report)
            print(f"\n[+] Report written: {args.json}\n[+] Report SHA-256: {digest} (unsigned integrity aid, not a custody record)")
        return 0
    except ArchiveLimitError as exc:
        print(f"[!] Refused: {exc}")
        return 2
    except Exception as exc:
        print(f"\n[!] Analysis failed: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
