import re
from urllib.parse import urlparse
from androguard.core.apk import APK

def analyze_apk_file(apk_path):
    """APK ko read karke metadata aur endpoints nikaalta hai"""
    apk = APK(apk_path)
    
    data = {
        "app_name": apk.get_app_name(),
        "package_name": apk.get_package(),
        "permissions": apk.get_permissions(),
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "urls": [],
        "api_routes": [],
        "endpoint_details": []
    }

    extracted_urls = set()
    api_routes = set()

    # APK ki compiled DEX files ke andar se URLs aur API routes nikaalna
    for dex in apk.get_all_dex():
        # 1. HTTP/HTTPS URLs dhoondhna
        found_urls = re.findall(b'https?://[^\s"\'<>]+', dex)
        for u in found_urls:
            try:
                dec = u.decode('utf-8', errors='ignore')
                ignore_list = ["schemas.android.com", "w3.org", "apache.org", "xmlpull.org", "google.com/schemas"]
                if not any(ig in dec for ig in ignore_list):
                    extracted_urls.add(dec)
            except:
                pass

        # 2. Relative API paths dhoondhna (e.g. /api/v1/login)
        found_routes = re.findall(b'/(?:api|v1|v2|v3|auth|user|admin|data)/[a-zA-Z0-9_/-]+', dex)
        for r in found_routes:
            try:
                api_routes.add(r.decode('utf-8', errors='ignore'))
            except:
                pass

    data["urls"] = list(extracted_urls)[:25]
    data["api_routes"] = list(api_routes)[:20]

    # Endpoint domain aur path breakdown
    for u in data["urls"]:
        parsed = urlparse(u)
        domain = parsed.netloc
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(':')[0]))
        data["endpoint_details"].append({
            "Full Endpoint": u,
            "Server / Domain": domain,
            "API Path": parsed.path if parsed.path else "/",
            "Type": "Direct IP" if is_ip else "Domain",
            "Protocol": parsed.scheme.upper()
        })

    return data