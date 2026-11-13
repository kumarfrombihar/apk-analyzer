import hashlib
import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import streamlit as st
from extractor import API_ROUTE_RE, analyze_apk_file
from ai_agent import ask_offline_ai
from apkanalyze import analyze_path
from apkanalyze import display_destination
from validate_report import validate_json_schema, validate_references, validate_structural


@st.cache_data(ttl=3600)
def resolve_host_ip(host: str) -> str:
    """
    Host agar domain name hai toh uska live IP address resolve karta hai.
    Agar pehle se direct IP hai, toh wahi IP show karta hai.
    Agar offline hai ya domain resolve na ho, toh graceful fallback return karta hai.
    """
    clean_host = host.split(":")[0].strip("[]").strip()
    if not clean_host:
        return "-"

    # Pehle check karo ki kya yeh pehle se valid IP hai
    try:
        ipaddress.ip_address(clean_host)
        return clean_host
    except ValueError:
        pass

    # Domain se IP address resolve karna
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyname(clean_host)
    except (socket.gaierror, socket.timeout, OSError):
        return "Offline / Unresolved"


def humanize_component(full_class_name, comp_type="activity"):
    """
    Converts raw technical class names (e.g. org.telegram.ui.ExternalActionActivity)
    into a human-readable title with an intuitive icon.
    """
    if not full_class_name:
        return "❓ Unknown Component", ""

    class_name = full_class_name.split(".")[-1]
    spaced_name = re.sub(r"([a-z])([A-Z])", r"\1 \2", class_name)
    lowered = class_name.lower()

    if "splash" in lowered or "launch" in lowered:
        title = "🚀 App Launch / Splash Screen"
    elif "main" in lowered or "home" in lowered:
        title = "🏠 Main Dashboard / Home Screen"
    elif "login" in lowered or "auth" in lowered or "signin" in lowered:
        title = "🔐 Login & Authentication"
    elif "register" in lowered or "signup" in lowered:
        title = "📝 User Registration"
    elif "setting" in lowered or "pref" in lowered:
        title = "⚙️ App Settings & Preferences"
    elif "externalaction" in lowered or "action" in lowered:
        title = "🔗 External Intent / Action Handler"
    elif "chat" in lowered or "message" in lowered or "conversation" in lowered:
        title = "💬 Chat & Messaging Screen"
    elif "profile" in lowered or "account" in lowered or "user" in lowered:
        title = "👤 User Profile"
    elif "share" in lowered:
        title = "📤 Sharing Interface"
    elif "media" in lowered or "player" in lowered or "video" in lowered or "audio" in lowered:
        title = "🎬 Media & Content Player"
    elif "camera" in lowered or "photo" in lowered or "image" in lowered:
        title = "📷 Camera & Photo Capture"
    elif "file" in lowered or "document" in lowered or "download" in lowered:
        title = "📁 File & Download Manager"
    elif "notification" in lowered:
        title = "🔔 Notification Handler"
    elif "sync" in lowered or "worker" in lowered or "job" in lowered:
        title = "🔄 Background Sync Engine"
    elif comp_type == "service":
        title = f"⚙️ Background Service ({spaced_name})"
    elif comp_type == "receiver":
        title = f"📡 System Broadcast Listener ({spaced_name})"
    else:
        title = f"📱 {spaced_name}"

    return title, full_class_name


def humanize_permission(perm_string):
    """
    Classifies an Android permission into User-Prompted (Dangerous) vs Auto-Granted (Normal)
    and maps it to an intuitive icon and human-understandable name.
    """
    p_upper = perm_string.upper()

    perm_map = {
        # Storage & Media
        "READ_EXTERNAL_STORAGE": ("📁 Access Photos, Media & Files", True),
        "WRITE_EXTERNAL_STORAGE": ("💾 Save & Modify Files on Storage", True),
        "MANAGE_EXTERNAL_STORAGE": ("🗄️ Full File Management Access", True),
        "READ_MEDIA_IMAGES": ("🖼️ Read Photos & Images", True),
        "READ_MEDIA_VIDEO": ("🎥 Read Videos", True),
        "READ_MEDIA_AUDIO": ("🎵 Read Audio Tracks", True),
        # Camera & Mic
        "CAMERA": ("📷 Take Pictures & Record Video", True),
        "RECORD_AUDIO": ("🎙️ Record Audio / Microphone", True),
        # Location
        "ACCESS_FINE_LOCATION": ("📍 Precise GPS Location", True),
        "ACCESS_COARSE_LOCATION": ("🗺️ Approximate Network Location", True),
        "ACCESS_BACKGROUND_LOCATION": ("🛰️ Background Location Tracking", True),
        # Contacts & Identity
        "READ_CONTACTS": ("👥 Read Phone Contacts", True),
        "WRITE_CONTACTS": ("👤 Add & Modify Contacts", True),
        "GET_ACCOUNTS": ("🆔 Access Device Accounts List", True),
        # Phone & Calls
        "READ_PHONE_STATE": ("📞 Read Phone Status & Device ID", True),
        "CALL_PHONE": ("📱 Make Phone Calls Directly", True),
        "READ_CALL_LOG": ("📋 Read Call History Logs", True),
        "WRITE_CALL_LOG": ("✏️ Modify Call History Logs", True),
        "ANSWER_PHONE_CALLS": ("📲 Answer Incoming Phone Calls", True),
        # SMS
        "SEND_SMS": ("💬 Send SMS Messages", True),
        "RECEIVE_SMS": ("📥 Receive & Read Incoming SMS", True),
        "READ_SMS": ("✉️ Read Stored SMS Messages", True),
        "RECEIVE_MMS": ("📨 Receive Multimedia Messages", True),
        # Biometrics & Sensors
        "USE_BIOMETRIC": ("👆 Use Fingerprint / Face Unlock", True),
        "USE_FINGERPRINT": ("👆 Use Fingerprint Sensor", True),
        "BODY_SENSORS": ("❤️ Access Heart Rate & Body Sensors", True),
        "ACTIVITY_RECOGNITION": ("🏃 Track Physical Activity / Steps", True),
        # Standard / Automatic Permissions
        "INTERNET": ("🌐 Full Internet Access", False),
        "ACCESS_NETWORK_STATE": ("📶 View Network Connections", False),
        "ACCESS_WIFI_STATE": ("📡 View Wi-Fi State", False),
        "CHANGE_WIFI_STATE": ("🔄 Connect/Disconnect Wi-Fi", False),
        "VIBRATE": ("📳 Control Device Vibration", False),
        "WAKE_LOCK": ("⚡ Prevent Phone from Sleeping", False),
        "RECEIVE_BOOT_COMPLETED": ("🚀 Automatically Run at Startup", False),
        "POST_NOTIFICATIONS": ("🔔 Show App Notifications", True),
        "FOREGROUND_SERVICE": ("⚙️ Run Ongoing Background Service", False),
        "BLUETOOTH": ("📶 Pair with Bluetooth Devices", False),
        "BLUETOOTH_ADMIN": ("⚙️ Discover Bluetooth Devices", False),
        "BLUETOOTH_CONNECT": ("🔗 Connect to Bluetooth Devices", True),
        "BLUETOOTH_SCAN": ("🔍 Search for Nearby Bluetooth Devices", True),
        "REQUEST_INSTALL_PACKAGES": ("📦 Install Other Unknown Apps", True),
    }

    short_perm = perm_string.split(".")[-1]
    if short_perm in perm_map:
        friendly_name, is_user_prompted = perm_map[short_perm]
        return friendly_name, perm_string, is_user_prompted

    sensitive_keywords = ["LOCATION", "CAMERA", "AUDIO", "SMS", "CONTACT", "STORAGE", "PHONE", "RECORD", "BIOMETRIC"]
    is_sensitive = any(k in p_upper for k in sensitive_keywords)

    clean_label = re.sub(r"([a-z])([A-Z])", r"\1 \2", short_perm).replace("_", " ").title()
    icon = "⚠️" if is_sensitive else "ℹ️"
    return f"{icon} {clean_label}", perm_string, is_sensitive


def classify_endpoint_direction(endpoint):
    """
    Analyzes whether an endpoint is a Direct IP, outbound (sending data from phone),
    inbound (fetching resource/media to phone), or a general API route.
    """
    full_url = (endpoint.get("Full Endpoint") or "").lower()
    path = (endpoint.get("API Path") or "").lower()
    target_type = endpoint.get("Type") or ""
    host = (endpoint.get("Server / Domain") or "").lower()

    is_ip = target_type == "Direct IP" or bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]))

    outbound_keywords = [
        "upload", "collect", "telemetry", "track", "analytics", "log", 
        "metric", "report", "beacon", "stat", "crash", "feedback", "event",
        "submit", "post", "sync", "push", "register"
    ]

    inbound_keywords = [
        "download", "asset", "cdn", "static", "media", "image", "photo",
        "video", "audio", "font", "content", "stream", "get", "fetch",
        "update", "res", "resource", "file"
    ]

    has_outbound = any(k in path or k in full_url for k in outbound_keywords)
    has_inbound = any(k in path or k in full_url for k in inbound_keywords)

    if is_ip:
        category = "ip"
        label = "⚠️ Direct IP Address"
        desc = "Server identified by raw IP instead of domain name"
    elif has_outbound:
        category = "outbound"
        label = "📤 Data Sent (Phone → Server)"
        desc = "Endpoint indicates telemetry, tracking, logs, or user data upload"
    elif has_inbound:
        category = "inbound"
        label = "📥 Resource Received (Server → Phone)"
        desc = "Endpoint indicates media, configuration, static assets, or download"
    else:
        category = "general"
        label = "🔗 General Backend API"
        desc = "Standard server communication / API endpoint"

    return category, label, desc


def rdap_lookup_target(host):
    """Return a public RDAP lookup target, or None for local/private hosts."""
    host = host.strip().strip("[]").rstrip(".")
    if not host:
        return None

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or host.lower().endswith(
            (".local", ".internal", ".lan", ".home", ".test", ".invalid", ".example")
        ):
            return None
        return "domain", host

    return ("ip", host) if address.is_global else None


def fetch_rdap_record(target_type, value):
    """Fetch and summarize one examiner-requested record from rdap.org."""
    url = f"https://rdap.org/{target_type}/{quote(value, safe='')}"
    request = Request(url, headers={"Accept": "application/rdap+json, application/json"})

    try:
        with urlopen(request, timeout=15) as response:
            data = json.loads(response.read())
    except HTTPError as error:
        raise RuntimeError(f"RDAP returned HTTP {error.code}.") from error
    except (URLError, TimeoutError) as error:
        raise RuntimeError(f"RDAP lookup failed: {error}") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError("RDAP returned invalid JSON.") from error

    if not isinstance(data, dict):
        raise RuntimeError("RDAP returned an unexpected response.")

    organizations = set()

    def collect_organizations(entities):
        for entity in entities or []:
            for card in (entity.get("vcardArray") or [None, []])[1]:
                if len(card) > 3 and str(card[0]).lower() in {"fn", "org"}:
                    value_text = card[3]
                    if isinstance(value_text, list):
                        value_text = " ".join(str(part) for part in value_text)
                    if value_text:
                        organizations.add(str(value_text))
            collect_organizations(entity.get("entities"))

    collect_organizations(data.get("entities"))
    registration = next(
        (
            event.get("eventDate")
            for event in data.get("events", [])
            if "registration" in str(event.get("eventAction", "")).lower()
        ),
        None,
    )
    network = None
    if data.get("startAddress") and data.get("endAddress"):
        network = f"{data['startAddress']} – {data['endAddress']}"

    return {
        "name": data.get("ldhName") or data.get("handle") or data.get("name"),
        "organization": ", ".join(sorted(organizations)[:2]),
        "country": data.get("country"),
        "network": network,
        "registration": registration,
        "status": ", ".join(data.get("status", [])[:3]),
        "url": url,
    }


def build_bundle_view_data(report):
    """Adapt APKM split findings to the existing single-APK report panels."""
    components = report["components"]
    package_names = sorted({item.get("package", "") for item in components if item.get("package")})
    bundle_info = (report.get("bundle") or {}).get("info_json") or {}
    app_name = bundle_info.get("app_name") or bundle_info.get("apk_title") or (
        package_names[0] if package_names else "Unknown Application"
    )
    permissions = set()
    component_names = {"activities": set(), "services": set(), "receivers": set()}

    for item in components:
        behavior = item.get("behavior_analysis") or {}
        permissions.update(behavior.get("requested_permissions", []))
        for kind, names in component_names.items():
            names.update(
                component.get("name", "")
                for component in behavior.get("components", {}).get(kind, [])
                if component.get("name")
            )

    endpoint_details = []
    api_routes = set()
    for destination in report.get("destinations", []):
        normalized = destination.get("normalized") or {}
        host = normalized.get("host", "")
        scheme = normalized.get("scheme")
        kind = destination.get("kind", "")
        display = display_destination(normalized)
        endpoint_type = "Direct IP" if kind == "ip" else "Domain"
        protocol = scheme.upper() if scheme else ("TCP/IP" if kind == "ip" else "HTTP/S")
        endpoint_details.append({
            "Full Endpoint": display,
            "Server / Domain": host,
            "Port": str(normalized.get("port") or "-"),
            "API Path": normalized.get("path") or "/",
            "Type": endpoint_type,
            "Protocol": protocol,
            "Decoded Via": next(
                (
                    occurrence.get("decoded_via") or "Direct"
                    for occurrence in destination.get("occurrences", [])
                    if occurrence.get("decoded_via")
                ),
                "Direct",
            ),
        })
        api_routes.update(API_ROUTE_RE.findall(normalized.get("path") or ""))

    return {
        "app_name": app_name,
        "package_name": ", ".join(package_names) or "Unknown Package",
        "permissions": sorted(permissions),
        "activities": sorted(component_names["activities"]),
        "services": sorted(component_names["services"]),
        "receivers": sorted(component_names["receivers"]),
        "urls": [item["Full Endpoint"] for item in endpoint_details],
        "api_routes": sorted(api_routes)[:100],
        "endpoint_details": endpoint_details,
    }


def render_endpoint_table(endpoints, section_key):
    """Reusable helper to display a clean table of endpoints with IP resolution and RDAP lookup."""
    if not endpoints:
        st.caption("No endpoints found in this category.")
        return

    headers = [
        "Endpoint URL",
        "Host / Domain",
        "IP Address",
        "Port",
        "Target Type",
        "Scheme",
        "Detection Source",
        "Lookup",
    ]
    column_widths = [2.4, 1.4, 1.3, 0.6, 0.9, 0.7, 1.1, 0.9]
    for column, header in zip(st.columns(column_widths), headers):
        column.markdown(f"**{header}**")

    rdap_results = st.session_state.setdefault("rdap_results", {})
    for index, endpoint in enumerate(endpoints):
        columns = st.columns(column_widths)
        host = endpoint.get("Server / Domain", "")
        resolved_ip = resolve_host_ip(host)

        row_values = (
            endpoint.get("Full Endpoint", ""),
            host,
            resolved_ip,
            endpoint.get("Port", ""),
            endpoint.get("Type", ""),
            endpoint.get("Protocol", ""),
            endpoint.get("Decoded Via", ""),
        )
        for col, val in zip(columns[:-1], row_values):
            col.write(val)

        target = rdap_lookup_target(host)
        lookup_column = columns[-1]
        if target is None:
            lookup_column.caption("Private/local")
            continue

        target_type, value = target
        target_key = f"{target_type}:{value}"
        button_id = f"rdap_lookup_{section_key}_{index}_{target_key}"
        with lookup_column:
            if st.button("Lookup", key=button_id):
                with st.spinner(f"Querying rdap.org for {value}..."):
                    try:
                        rdap_results[target_key] = {
                            "record": fetch_rdap_record(target_type, value),
                            "error": None,
                        }
                    except RuntimeError as error:
                        rdap_results[target_key] = {"record": None, "error": str(error)}

            result = rdap_results.get(target_key)
            if result and result["error"]:
                st.error(result["error"])
            elif result and result["record"]:
                record = result["record"]
                details = [
                    v for v in (
                        record["name"],
                        record["organization"],
                        record["country"],
                        record["network"],
                        record["registration"],
                        record["status"],
                    )
                    if v
                ]
                st.caption(" · ".join(details) or "No registration details provided.")
                st.markdown(f"[Open RDAP record]({record['url']})")


# Page Setup
st.set_page_config(
    page_title="Netra Lab Mumbai | APK Decompiler",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Deep Blue & Corporate Slate Security Theme CSS
st.markdown("""
<style>
    .stApp {
        background-color: #0a0f1d;
        color: #e2e8f0;
    }

    .lab-banner {
        background: linear-gradient(180deg, #111c35 0%, #0c1427 100%);
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 24px 20px;
        text-align: center;
        margin-bottom: 26px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.45);
    }
    .lab-title {
        color: #f8fafc;
        font-size: 28px;
        font-weight: 800;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin: 0;
    }
    .lab-sub {
        color: #38bdf8;
        font-size: 14px;
        font-weight: 700;
        letter-spacing: 1.5px;
        margin-top: 6px;
        text-transform: uppercase;
    }
    .lab-desc {
        color: #94a3b8;
        font-size: 13px;
        margin-top: 4px;
    }

    .upload-card-wrapper {
        background: #111a2e;
        border: 1px solid #1e2d4a;
        border-radius: 14px;
        padding: 24px;
        text-align: center;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
        margin-bottom: 18px;
    }
    .upload-card-icon {
        font-size: 36px;
        margin-bottom: 8px;
    }
    .upload-card-title {
        color: #f1f5f9;
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .upload-card-subtitle {
        color: #94a3b8;
        font-size: 13px;
    }

    div[data-testid="stFileUploader"] {
        background: #090e1a;
        border: 1px dashed #243552;
        border-radius: 12px;
        padding: 20px;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    div[data-testid="stFileUploader"]:hover {
        border-color: #38bdf8;
        box-shadow: 0 0 16px rgba(56, 189, 248, 0.15);
    }
    div[data-testid="stFileUploader"] section {
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
        justify-content: center !important;
        text-align: center !important;
    }
    div[data-testid="stFileUploader"] section button {
        margin: 10px auto 0 auto !important;
        display: block !important;
        background-color: #1e293b;
        color: #f8fafc;
        border: 1px solid #334155;
        border-radius: 6px;
        font-weight: 600;
    }
    div[data-testid="stFileUploader"] section button:hover {
        background-color: #2563eb;
        border-color: #2563eb;
        color: #ffffff;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, #111a2e 0%, #0d1527 100%);
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 14px 18px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.25);
    }
    div[data-testid="stMetric"] label {
        color: #94a3b8 !important;
        font-size: 13px !important;
        font-weight: 600;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 700;
    }

    button[data-baseweb="tab"] {
        font-size: 14px;
        font-weight: 600;
        color: #94a3b8 !important;
        padding: 10px 18px;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #38bdf8 !important;
        border-bottom-color: #38bdf8 !important;
    }

    .badge-danger {
        color: #f87171;
        background-color: rgba(239, 68, 68, 0.12);
        border: 1px solid rgba(239, 68, 68, 0.25);
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }
    .badge-normal {
        color: #94a3b8;
        background-color: rgba(148, 163, 184, 0.1);
        border: 1px solid rgba(148, 163, 184, 0.2);
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)

# Ensure temp directory exists
os.makedirs("temp_apks", exist_ok=True)

# Sidebar
with st.sidebar:
    st.markdown("### 🔬 NETRA LABS")
    st.caption("Forensics & Threat Intelligence Unit")
    st.markdown("---")

    st.subheader("Configuration")
    model_choice = st.text_input("Ollama Model:", value="llama3.2:3b")
    st.caption("Offline inference via workstation hardware.")

    st.markdown("---")
    st.markdown("**Lab Node:** Mumbai")
    st.success("● Engine: Offline Ready")
    st.info("● Mode: Static Reverse Audit")
    st.caption("Upload an APK or split package bundle for the same analysis report.")

# Header Banner
st.markdown("""
<div class="lab-banner">
    <div class="lab-title">NETRA LAB MUMBAI</div>
    <div class="lab-sub">APK DECOMPILER & STATIC ANALYZER</div>
    <div class="lab-desc">Offline Mobile Application Reverse Engineering & Security Intelligence</div>
</div>
""", unsafe_allow_html=True)

# Centered File Upload Card
col_left, col_center, col_right = st.columns([1, 2, 1])

with col_center:
    st.markdown("""
    <div class="upload-card-wrapper">
        <div class="upload-card-icon">📁</div>
        <div class="upload-card-title">Select Target Application Package</div>
        <div class="upload-card-subtitle">
            Drag and drop an <code>.apk</code> or split package bundle to start static analysis.
        </div>
    </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        label="Upload Target APK",
        type=["apk", "apkm", "xapk", "apks"],
        label_visibility="collapsed",
        help="Static analysis supports APK, APKM, XAPK, and APKS packages."
    )

if uploaded_file is not None:
    package_filename = os.path.basename(uploaded_file.name)
    package_content = uploaded_file.getvalue()
    package_sha256 = hashlib.sha256(package_content).hexdigest()
    cached_analysis = st.session_state.get("package_analysis")

    if (
        cached_analysis
        and cached_analysis["sha256"] == package_sha256
        and cached_analysis["filename"] == package_filename
    ):
        forensic_report = cached_analysis["forensic_report"]
        apk_data = cached_analysis["apk_data"]
    else:
        apk_path = os.path.join("temp_apks", package_filename)
        with open(apk_path, "wb") as f:
            f.write(package_content)

        with st.status("Analyzing package and building the report...", expanded=True) as status:
            forensic_report = analyze_path(apk_path)
            ledger_ids = validate_structural(forensic_report)
            validate_references(forensic_report, ledger_ids)
            schema_path = Path(__file__).with_name("report.schema.json")
            validate_json_schema(forensic_report, schema_path)
            status.update(label="Package analysis complete.", state="complete", expanded=False)

        if forensic_report["package_format"] == "APK":
            with st.status("Preparing Netra Lab report...", expanded=True) as status:
                apk_data = analyze_apk_file(apk_path)
                status.update(label="Report is ready.", state="complete", expanded=False)
        else:
            apk_data = build_bundle_view_data(forensic_report)

        st.session_state["package_analysis"] = {
            "sha256": package_sha256,
            "filename": package_filename,
            "forensic_report": forensic_report,
            "apk_data": apk_data,
        }

    st.markdown("---")

    # Target Metadata Header
    st.markdown(f"### 📦 Target: `{apk_data['app_name'] or 'Unknown Application'}`")
    st.markdown(f"**Package ID:** `{apk_data['package_name']}`")
    if forensic_report["package_format"] != "APK":
        st.caption(
            f"{forensic_report['package_format']} split package · "
            f"{len(forensic_report['components'])} APK components analyzed"
        )

    # Metrics Row
    total_components = len(apk_data["activities"]) + len(apk_data["services"]) + len(apk_data["receivers"])
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Permissions", len(apk_data["permissions"]))
    with m2:
        st.metric("Components", total_components)
    with m3:
        st.metric("Endpoints Found", len(apk_data["urls"]))
    with m4:
        st.metric("API Routes", len(apk_data["api_routes"]))

    st.markdown("###")

    # Tabbed Navigation Layout
    tab_overview, tab_perms, tab_network, tab_ai = st.tabs([
        "📊 Architecture Overview",
        "🔒 Permissions Audit",
        "🌐 Network & Endpoints",
        "🤖 AI Intelligence Report"
    ])

    with tab_overview:
        st.subheader("Component Structure (Human-Readable View)")
        st.caption("Technical class names are categorized into functional modules and UI screens.")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### 📱 User Screens & Activities")
            if apk_data["activities"]:
                for act in apk_data["activities"]:
                    title, raw_name = humanize_component(act, comp_type="activity")
                    with st.container():
                        st.markdown(f"**{title}**")
                        st.caption(f"`{raw_name}`")
            else:
                st.caption("No activities declared.")

        with c2:
            st.markdown("#### ⚙️ Background Services & Receivers")
            st.write("**Services:**")
            if apk_data["services"]:
                for srv in apk_data["services"]:
                    title, raw_name = humanize_component(srv, comp_type="service")
                    with st.container():
                        st.markdown(f"**{title}**")
                        st.caption(f"`{raw_name}`")
            else:
                st.caption("No background services declared.")

            st.write("**Broadcast Receivers:**")
            if apk_data["receivers"]:
                for rcv in apk_data["receivers"]:
                    title, raw_name = humanize_component(rcv, comp_type="receiver")
                    with st.container():
                        st.markdown(f"**{title}**")
                        st.caption(f"`{raw_name}`")
            else:
                st.caption("No broadcast receivers declared.")

    with tab_perms:
        st.subheader("Declared Permissions & Risk Indicators")
        st.caption("Permissions are separated into User-Prompted (Dangerous) and Auto-Granted (Install-Time) categories.")

        if apk_data["permissions"]:
            user_prompted = []
            auto_granted = []

            for p in apk_data["permissions"]:
                friendly_name, raw_p, is_user = humanize_permission(p)
                if is_user:
                    user_prompted.append((friendly_name, raw_p))
                else:
                    auto_granted.append((friendly_name, raw_p))

            col_p1, col_p2 = st.columns(2)

            with col_p1:
                st.markdown(f"#### ⚠️ User-Prompted Permissions (`{len(user_prompted)}`)")
                st.caption("Requires explicit user approval at runtime. Accesses sensitive data or hardware sensors.")
                if user_prompted:
                    for friendly_name, raw_p in user_prompted:
                        with st.container():
                            st.markdown(f"**{friendly_name}** &nbsp; <span class='badge-danger'>⚠️ Sensitive</span>", unsafe_allow_html=True)
                            st.caption(f"`{raw_p}`")
                else:
                    st.caption("No dangerous runtime permissions requested.")

            with col_p2:
                st.markdown(f"#### ℹ️ Auto-Granted Permissions (`{len(auto_granted)}`)")
                st.caption("Granted automatically by the Android system upon installation. Standard utility access.")
                if auto_granted:
                    for friendly_name, raw_p in auto_granted:
                        with st.container():
                            st.markdown(f"**{friendly_name}** &nbsp; <span class='badge-normal'>ℹ️ Standard</span>", unsafe_allow_html=True)
                            st.caption(f"`{raw_p}`")
                else:
                    st.caption("No automatic permissions requested.")
        else:
            st.info("No permissions requested by this application.")

    with tab_network:
        st.subheader("Network Endpoints & Traffic Flow Categorization")
        st.caption(
            "Endpoints are grouped by probable traffic intent (data sent vs resource fetched) "
            "and infrastructure type (raw IP vs domain name). Each server displays both its domain and resolved IP address."
        )

        all_endpoints = apk_data.get("endpoint_details", [])

        if all_endpoints:
            ip_list = []
            outbound_list = []
            inbound_list = []
            general_list = []

            for ep in all_endpoints:
                cat, _, _ = classify_endpoint_direction(ep)
                if cat == "ip":
                    ip_list.append(ep)
                elif cat == "outbound":
                    outbound_list.append(ep)
                elif cat == "inbound":
                    inbound_list.append(ep)
                else:
                    general_list.append(ep)

            nc1, nc2, nc3, nc4 = st.columns(4)
            with nc1:
                st.metric("Total Endpoints", len(all_endpoints))
            with nc2:
                st.metric("⚠️ Direct IPs", len(ip_list))
            with nc3:
                st.metric("📤 Data Outbound", len(outbound_list))
            with nc4:
                st.metric("📥 Resource Inbound", len(inbound_list))

            st.markdown("---")

            sub_tab_ips, sub_tab_outbound, sub_tab_inbound, sub_tab_general, sub_tab_all = st.tabs([
                f"⚠️ Direct IP Endpoints ({len(ip_list)})",
                f"📤 Data Sent / Outbound ({len(outbound_list)})",
                f"📥 Resources Fetched ({len(inbound_list)})",
                f"🔗 General APIs ({len(general_list)})",
                f"📋 All Endpoints ({len(all_endpoints)})"
            ])

            with sub_tab_ips:
                st.markdown("#### ⚠️ Direct IP Connections (Bina Domain Ke Seedhe IP)")
                st.caption("Servers identified directly by numeric IP address without a domain name.")
                render_endpoint_table(ip_list, "ips")

            with sub_tab_outbound:
                st.markdown("#### 📤 Phone Se Data Bhejne Wale Endpoints (Outbound)")
                st.caption("Endpoints identifying telemetry, analytics, tracking, logs, or data upload servers.")
                render_endpoint_table(outbound_list, "outbound")

            with sub_tab_inbound:
                st.markdown("#### 📥 Server Se Resource/Media Lene Wale Endpoints (Inbound)")
                st.caption("Endpoints used for downloading media, static assets, configuration, or updates.")
                render_endpoint_table(inbound_list, "inbound")

            with sub_tab_general:
                st.markdown("#### 🔗 General Backend APIs & Services")
                st.caption("Standard application backend routes and connected web services.")
                render_endpoint_table(general_list, "general")

            with sub_tab_all:
                st.markdown("#### 📋 Complete Extracted Endpoints List")
                render_endpoint_table(all_endpoints, "all")
        else:
            st.warning("No hardcoded HTTP/HTTPS endpoints discovered in this package.")

        st.markdown("#### 🚏 Extracted API Paths")
        if apk_data["api_routes"]:
            st.json(apk_data["api_routes"])
        else:
            st.caption("No relative API path patterns found.")

    with tab_ai:
        st.subheader("Netra Lab AI Assessment Report")
        ai_report_key = f"{package_sha256}:{model_choice}"
        ai_reports = st.session_state.setdefault("ai_reports", {})
        if ai_report_key not in ai_reports:
            with st.spinner("Offline AI model is evaluating findings..."):
                ai_reports[ai_report_key] = ask_offline_ai(apk_data, model_name=model_choice)
        ai_report = ai_reports[ai_report_key]

        st.markdown(ai_report)
        st.markdown("---")
        st.download_button(
            label="📥 Download Netra Lab Report (.md)",
            data=ai_report,
            file_name=f"NetraLab_{apk_data['app_name'] or 'APK'}_Report.md",
            mime="text/markdown"
        )