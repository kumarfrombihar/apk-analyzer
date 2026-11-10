import os
import streamlit as st
from extractor import analyze_apk_file
from ai_agent import ask_offline_ai

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
    /* Global Base */
    .stApp {
        background-color: #0a0f1d;
        color: #e2e8f0;
    }

    /* Netra Lab Header Banner - Corporate Slate */
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

    /* Centered Upload Card Container */
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

    /* Centered File Uploader Box & Inner Button */
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

    /* Metric Cards - Deep Slate */
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

    /* Tab Customization */
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

    /* Badges */
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
            Drag and drop your <code>.apk</code> file into the area below to start decompilation and analysis.
        </div>
    </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        label="Upload Target APK",
        type=["apk"],
        label_visibility="collapsed",
        help="Upload an Android APK file to inspect permissions, DEX bytecode, components, and hardcoded routes."
    )

if uploaded_file is not None:
    apk_path = os.path.join("temp_apks", uploaded_file.name)
    with open(apk_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    with st.status("Decompiling APK & extracting metadata...", expanded=True) as status:
        apk_data = analyze_apk_file(apk_path)
        status.update(label="Decompilation and Extraction Successful!", state="complete", expanded=False)

    st.markdown("---")

    # Target Metadata Header
    st.markdown(f"### 📦 Target: `{apk_data['app_name'] or 'Unknown Application'}`")
    st.markdown(f"**Package ID:** `{apk_data['package_name']}`")

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
        st.subheader("Component Structure")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### 📱 Declared Activities")
            if apk_data["activities"]:
                for act in apk_data["activities"]:
                    st.code(act, language="bash")
            else:
                st.caption("No activities declared.")
        with c2:
            st.markdown("#### ⚙️ Background Services & Receivers")
            st.write("**Services:**")
            if apk_data["services"]:
                for srv in apk_data["services"]:
                    st.code(srv, language="bash")
            else:
                st.caption("No services declared.")

            st.write("**Broadcast Receivers:**")
            if apk_data["receivers"]:
                for rcv in apk_data["receivers"]:
                    st.code(rcv, language="bash")
            else:
                st.caption("No receivers declared.")

    with tab_perms:
        st.subheader("Declared Permissions & Risk Indicators")
        if apk_data["permissions"]:
            sensitive_keywords = ["LOCATION", "CAMERA", "RECORD_AUDIO", "SMS", "CONTACTS", "STORAGE", "READ_PHONE_STATE"]
            p_cols = st.columns(2)
            for i, p in enumerate(apk_data["permissions"]):
                col_target = p_cols[i % 2]
                is_sensitive = any(word in p.upper() for word in sensitive_keywords)
                badge = '<span class="badge-danger">⚠️ Sensitive</span>' if is_sensitive else '<span class="badge-normal">ℹ️ Standard</span>'
                col_target.markdown(f"- `{p}` &nbsp; {badge}", unsafe_allow_html=True)
        else:
            st.info("No permissions requested.")

    with tab_network:
        st.subheader("Extracted Endpoints & Domains")
        if apk_data["endpoint_details"]:
            st.dataframe(
                apk_data["endpoint_details"],
                use_container_width=True,
                column_config={
                    "Full Endpoint": st.column_config.LinkColumn("Endpoint URL"),
                    "Type": st.column_config.TextColumn("Target Type"),
                    "Protocol": st.column_config.TextColumn("Scheme")
                }
            )
        else:
            st.warning("No hardcoded HTTP/HTTPS endpoints discovered.")

        st.markdown("#### 🚏 Extracted API Paths")
        if apk_data["api_routes"]:
            st.json(apk_data["api_routes"])
        else:
            st.caption("No relative API path patterns found.")

    with tab_ai:
        st.subheader("Netra Lab AI Assessment Report")
        with st.spinner("Offline AI model is evaluating findings..."):
            ai_report = ask_offline_ai(apk_data, model_name=model_choice)

        st.markdown(ai_report)
        st.markdown("---")
        st.download_button(
            label="📥 Download Netra Lab Report (.md)",
            data=ai_report,
            file_name=f"NetraLab_{apk_data['app_name'] or 'APK'}_Report.md",
            mime="text/markdown"
        )