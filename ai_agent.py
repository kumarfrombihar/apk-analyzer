import ollama

def ask_offline_ai(apk_data, model_name="llama3.2:3b"):
    """
    Sends extracted APK metadata to the local Ollama LLM
    and generates an automated static analysis report in English.
    """
    
    prompt = f"""
    You are an expert Mobile Application Security & Static Analysis AI Agent.
    Analyze the following static metadata extracted from an Android APK and generate a structured technical report:

    ### 1. Application Functionality Overview
    - Based on the app name, package identifier, components, and permissions, summarize what this application is designed to do.

    ### 2. Endpoint & Network Analysis
    - Review the extracted network URLs and API routes.
    - Identify backend servers, third-party services, APIs, or cloud providers the application connects to.
    - Describe the probable nature of communication (e.g., analytics, authentication, data synchronization).

    ### 3. Permissions & Privacy Audit
    - Identify sensitive permissions (e.g., Location, Camera, Microphone, Contacts, Storage, SMS).
    - Assess whether the requested permissions align with the expected application functionality.

    ---
    **Extracted APK Metadata:**
    - App Name: {apk_data.get('app_name')}
    - Package Name: {apk_data.get('package_name')}
    - Permissions: {apk_data.get('permissions')}
    - Activities: {apk_data.get('activities', [])[:15]}
    - Services: {apk_data.get('services', [])[:15]}
    - Extracted URLs / Endpoints: {apk_data.get('urls')}
    - API Routes: {apk_data.get('api_routes')}
    """

    response = ollama.chat(
        model=model_name,
        messages=[{"role": "user", "content": prompt}]
    )
    return response['message']['content']