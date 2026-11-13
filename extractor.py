import base64
import binascii
import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit
from androguard.core.apk import APK

# ----------------- REGEX PATTERNS -----------------
URL_RE = re.compile(r"(?:https?|wss?)://[^\x00-\x20\"'<>\\]+", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
HOSTPORT_RE = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}):(\d{1,5})$")
DOMAIN_LITERAL_RE = re.compile(
    r"^(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d+)?(?:/[^\s?#]*)?(?:\?[^\s#]*)?(?:#\S*)?$",
    re.IGNORECASE,
)
API_ROUTE_RE = re.compile(r"/(?:api|v1|v2|v3|auth|user|admin|data|service|gateway)/[a-zA-Z0-9_/-]+", re.IGNORECASE)

# File extensions frequently mistaken for domain TLDs
NON_DOMAIN_SUFFIXES = {
    "apk", "arsc", "class", "csv", "dat", "db", "dex", "dtd", "html", "idx", "java", "json", "kt",
    "list", "map", "mf", "mp3", "mp4", "otf", "pb", "png", "properties", "proto", "jpg", "rsa", "sf",
    "so", "svg", "text", "ttf", "txt", "wav", "webp", "xml", "xsd",
}

# Accepted generic and country-code TLDs
KNOWN_TLDS = set(
    "com org net edu gov mil int io dev app ai co info biz xyz cloud me tv uk de fr jp in au ca us ch nl "
    "se no fi es it br ru cn tw kr sg id nz za mx eu tech shop site online store live news work zone team "
    "link host help world systems network agency mobi name coop museum travel pro asia arpa google amazon "
    "microsoft apple bank insurance jobs cat aero post xxx tel onion".split()
)

# Standard Android / Java namespaces to reject as domains
CODE_PACKAGE_ROOTS = {
    "java", "javax", "kotlin", "kotlinx", "android", "androidx", "dalvik", "jdk", "sun", "libcore",
    "okhttp3", "okio", "retrofit2", "google", "apache", "github", "jetbrains", "dispatchers", "clazz",
}

# Common noise patterns (schemas, licenses, stores, placeholders)
NOISE_PATTERNS = (
    ("schema_or_namespace", ("w3.org", "xmlsoap.org", "schemas.android.com", "schemas.microsoft.com", "schema.org", "xmlpull.org")),
    ("license_or_documentation", ("apache.org/licenses", "opensource.org/licenses", "creativecommons.org")),
    ("app_store", ("play.google.com/store", "apps.apple.com")),
    ("placeholder", ("example.com", "example.org", "example.net")),
)


# ----------------- VALIDATION HELPERS -----------------
def is_valid_ip(value: str) -> bool:
    """Validate whether a string is a well-formed IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def canonical_host(host: str) -> str:
    """Convert an IP or domain into canonical/Punycode form."""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            return host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return host.lower()


def is_valid_domain(value: str, is_bare: bool = False) -> bool:
    """
    Validate domains while filtering reverse-DNS, namespaces, and code packages.
    If is_bare is True, applies strict filtering against code identifiers (PascalCase/CamelCase).
    """
    # Bare code identifiers like 'Dispatchers.IO' or 'clazz.name' should be rejected
    if is_bare:
        # If contains uppercase (e.g. PascalCase/CamelCase class reference like Dispatchers.IO)
        if any(c.isupper() for c in value):
            return False

    value = value.lower().rstrip(".")
    if len(value) > 253 or is_valid_ip(value):
        return False

    labels = value.split(".")
    if len(labels) < 2 or len(labels) > 6 or not labels[-1].isalpha():
        return False

    if value.endswith((".arpa", ".invalid", ".test", ".example", ".localhost", ".local", ".internal")):
        return False

    if labels[0] in {"com", "org", "net", "edu", "gov", "mil", "io", "co", "app", "dev", "ai"}:
        return False

    if labels[0] in CODE_PACKAGE_ROOTS:
        return False

    if labels[-1] in NON_DOMAIN_SUFFIXES or labels[-1] not in KNOWN_TLDS:
        return False

    return all(1 <= len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels)


def normalize_url(value: str) -> str | None:
    """Sanitize and validate a URL string."""
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
        if not is_valid_ip(host) and not is_valid_domain(host, is_bare=False):
            return None
        return value
    except ValueError:
        return None


def is_noise(endpoint_display: str) -> bool:
    """Detect non-functional boilerplate like XML namespaces and license URLs."""
    lowered = endpoint_display.lower()
    for _, needles in NOISE_PATTERNS:
        if any(needle in lowered for needle in needles):
            return True
    return False


def decode_attempts(raw: str):
    """
    Attempt decoding constant Base64, Hex, or reversed string encodings.
    Yields tuples of (method_name, decoded_string).
    """
    s = raw.strip()
    if not (16 <= len(s) <= 2048) or re.search(r"\s", s):
        return

    # Hex Decode Check
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try:
            data = bytes.fromhex(s)
            if all(0x20 <= b < 0x7F for b in data):
                yield ("Hex", data.decode("ascii"))
        except ValueError:
            pass

    # Base64 Decode Check
    if re.fullmatch(r"[A-Za-z0-9+/_=-]+", s):
        std = s.replace("-", "+").replace("_", "/")
        try:
            data = base64.b64decode(std + "=" * (-len(std) % 4), validate=True)
            if all(0x20 <= b < 0x7F for b in data):
                yield ("Base64", data.decode("ascii"))
        except (binascii.Error, ValueError):
            pass

    # Reversed URL Check
    reversed_text = s[::-1]
    if "://" in reversed_text:
        yield ("Reversed", reversed_text)


def extract_candidates_from_text(text: str) -> list[tuple[str, str, str, str, str | None]]:
    """
    Parse a string and return matching destinations.
    Returns: list of (kind, host, port_str, full_target, path)
    """
    stripped = text.strip()
    found = []
    covered_hosts = set()

    # 1. Match Host:Port pairs (e.g. 192.168.1.1:8080 or api.example.com:443)
    hostport = HOSTPORT_RE.fullmatch(stripped)
    if hostport:
        host, port_val = hostport.group(1), int(hostport.group(2))
        if 1 <= port_val <= 65535:
            if is_valid_ip(host):
                can_ip = canonical_host(host)
                found.append(("IP", can_ip, str(port_val), stripped, "/"))
                covered_hosts.add(can_ip)
            elif is_valid_domain(host, is_bare=True):
                can_dom = canonical_host(host)
                found.append(("Domain", can_dom, str(port_val), stripped, "/"))
                covered_hosts.add(can_dom)
            if found:
                return found

    # 2. Match URLs / WebSockets
    for match in URL_RE.finditer(text):
        url = normalize_url(match.group(0))
        if url:
            parsed = urlsplit(url)
            host = canonical_host(parsed.hostname or "")
            kind = "Websocket" if parsed.scheme.lower() in ("ws", "wss") else "URL"
            try:
                port = str(parsed.port) if parsed.port else ("443" if "https" in parsed.scheme or "wss" in parsed.scheme else "80")
            except ValueError:
                port = "-"
            found.append((kind, host, port, url, parsed.path or "/"))
            covered_hosts.add(host)

    # 3. Match standalone IP addresses
    for match in IP_RE.finditer(text):
        ip = match.group(0)
        if is_valid_ip(ip):
            can_ip = canonical_host(ip)
            if can_ip not in covered_hosts:
                found.append(("IP", can_ip, "-", can_ip, "/"))
                covered_hosts.add(can_ip)

    # 4. Match Bare Domains (only if no URL/IP already found in the string)
    if not found:
        bare = DOMAIN_LITERAL_RE.fullmatch(stripped)
        if bare:
            raw_domain = bare.group(1)
            if is_valid_domain(raw_domain, is_bare=True):
                host = canonical_host(raw_domain)
                found.append(("Domain", host, "-", stripped, "/"))

    return found


# ----------------- MAIN ANALYSIS FUNCTION -----------------
def analyze_apk_file(apk_path: str) -> dict:
    """
    Decompiles APK to extract metadata, declared permissions,
    components, and network endpoints with obfuscation decoding and noise reduction.
    """
    try:
        apk = APK(apk_path)
    except Exception as e:
        return {
            "app_name": "Error Parsing APK",
            "package_name": f"Invalid APK ({e})",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "urls": [],
            "api_routes": [],
            "endpoint_details": []
        }

    app_name = apk.get_app_name()
    package_name = apk.get_package()

    data = {
        "app_name": str(app_name) if app_name else "Unknown Application",
        "package_name": str(package_name) if package_name else "Unknown Package",
        "permissions": apk.get_permissions() or [],
        "activities": apk.get_activities() or [],
        "services": apk.get_services() or [],
        "receivers": apk.get_receivers() or [],
        "urls": [],
        "api_routes": [],
        "endpoint_details": []
    }

    raw_strings = set()
    api_routes = set()

    # Extract strings and routes from DEX bytecode
    try:
        dex_files = apk.get_all_dex() or []
    except Exception:
        dex_files = []

    for dex in dex_files:
        if not dex:
            continue

        # 1. Regex string extraction (printable ASCII range)
        matches = re.findall(b'[\x20-\x7E]{4,}', dex)
        for m in matches:
            try:
                dec = m.decode('utf-8', errors='ignore').strip()
                if dec:
                    raw_strings.add(dec)
            except Exception:
                pass

        # 2. Relative API route detection
        try:
            found_routes = API_ROUTE_RE.findall(dex.decode('latin1', errors='ignore'))
            for r in found_routes:
                if not any(ig in r for ig in ["/data/misc", "/XmlSerializer", "/XmlPullParser", "/DevicePolicyManager"]):
                    api_routes.add(r)
        except Exception:
            pass

    extracted_endpoints = []
    seen_destinations = set()

    # Process all extracted strings
    for raw in raw_strings:
        if not (4 <= len(raw) <= 4096):
            continue

        candidates = extract_candidates_from_text(raw)
        detected_via = "Direct"

        # Attempt de-obfuscation if direct extraction yields nothing
        if not candidates:
            for method, decoded in decode_attempts(raw):
                candidates = extract_candidates_from_text(decoded)
                if candidates:
                    detected_via = method
                    break

        for kind, host, port, full_target, path in candidates:
            if is_noise(full_target):
                continue

            unique_key = (kind, host, port, full_target)
            if unique_key in seen_destinations:
                continue
            seen_destinations.add(unique_key)

            parsed = urlsplit(full_target) if kind in ("URL", "Websocket") else None
            protocol = parsed.scheme.upper() if parsed else ("TCP/IP" if kind == "IP" else "HTTP/S")
            target_type = "Direct IP" if (kind == "IP" or is_valid_ip(host)) else "Domain"

            extracted_endpoints.append({
                "Full Endpoint": full_target,
                "Server / Domain": host,
                "Port": port,
                "API Path": path,
                "Type": target_type,
                "Protocol": protocol,
                "Decoded Via": detected_via
            })

    # Sort and populate final lists
    data["endpoint_details"] = extracted_endpoints[:50]
    data["urls"] = [
        e["Full Endpoint"] for e in extracted_endpoints
        if e["Type"] == "Domain" or "http" in e["Full Endpoint"].lower()
    ][:25]
    data["api_routes"] = sorted(list(api_routes))[:20]

    return data
