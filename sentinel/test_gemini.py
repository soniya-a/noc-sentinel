import os
import sys
import json
import time
from pathlib import Path

# Load .env via python-dotenv if available
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env", override=False)
except ImportError:
    pass

def get_api_key():
    # 1. Environment variables (including those loaded by dotenv)
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    google_key = os.environ.get("GOOGLE_API_KEY", "").strip()

    if gemini_key and google_key:
        if gemini_key != google_key:
            print("Notice: Both GEMINI_API_KEY and GOOGLE_API_KEY are set with different values. Preferring GEMINI_API_KEY.")
        return gemini_key, "ENV (GEMINI_API_KEY)"
    if gemini_key:
        return gemini_key, "ENV (GEMINI_API_KEY)"
    if google_key:
        return google_key, "ENV (GOOGLE_API_KEY)"

    # 2. Check .streamlit/secrets.toml
    for secrets_path in [".streamlit/secrets.toml", os.path.expanduser("~/.streamlit/secrets.toml")]:
        if os.path.exists(secrets_path):
            try:
                import toml
                with open(secrets_path, "r") as f:
                    sec = toml.load(f)
                k = sec.get("GEMINI_API_KEY") or sec.get("GOOGLE_API_KEY") or sec.get("gemini_api_key")
                if k and str(k).strip():
                    return str(k).strip(), f"FILE ({secrets_path})"
            except Exception:
                pass

    # 3. Direct manual parse of .env (fallback if dotenv was not installed)
    for env_path in [".env", os.path.expanduser("~/.env")]:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        for prefix in ["GEMINI_API_KEY=", "GOOGLE_API_KEY="]:
                            if line.startswith(prefix):
                                val = line[len(prefix):].strip().strip('"').strip("'")
                                if val:
                                    return val, f"FILE ({env_path})"
            except Exception:
                pass

    return "", "NONE"

def inspect_env_file():
    """Inspects .env file safely without exposing any secret values."""
    env_file = Path(".env")
    if not env_file.exists():
        return False, "FILE_NOT_FOUND"
    
    with open(env_file, "r", errors="replace") as f:
        lines = f.readlines()
    
    has_gemini_var = False
    is_empty_val = True
    val_len = 0
    for line in lines:
        s = line.strip()
        if s.startswith("GEMINI_API_KEY="):
            has_gemini_var = True
            val = s[len("GEMINI_API_KEY="):].strip().strip('"').strip("'")
            if val:
                is_empty_val = False
                val_len = len(val)
    
    if not has_gemini_var:
        return True, "VARIABLE_MISSING"
    if is_empty_val:
        return True, "PLACEHOLDER_EMPTY"
    return True, f"CONFIGURED_LEN_{val_len}"

def test_gemini_request(api_key, model_name="gemini-2.5-flash"):
    import requests
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": "Reply with only: OK"}]}],
        "generationConfig": {
            "maxOutputTokens": 10,
            "temperature": 0.0
        }
    }

    t0 = time.time()
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        dt = time.time() - t0
    except requests.exceptions.Timeout:
        return False, f"Timeout after 15s connecting to Google Gemini API", 0
    except requests.exceptions.ConnectionError as e:
        return False, f"Connection error: {e}", 0
    except Exception as e:
        return False, f"Request exception: {e}", 0

    if resp.status_code == 200:
        try:
            data = resp.json()
            candidates = data.get("candidates", [])
            if candidates:
                text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
                return True, text, dt
            return True, "(Empty response content)", dt
        except Exception as e:
            return False, f"JSON parse error: {e}", dt
    else:
        err_msg = f"HTTP {resp.status_code}"
        try:
            err_json = resp.json()
            if "error" in err_json:
                detail = err_json["error"].get("message", "")
                status = err_json["error"].get("status", "")
                err_msg += f" [{status}]: {detail}"
        except Exception:
            err_msg += f" - {resp.text[:200]}"
        return False, err_msg, dt

if __name__ == "__main__":
    check_only = "--check-only" in sys.argv
    env_exists, env_state = inspect_env_file()
    key, src = get_api_key()

    print("=== GEMINI CONFIGURATION & DETECTION AUDIT ===")
    print(f".env File Exists: {env_exists}")
    print(f".env Key State  : {env_state}")
    print(f"Key Detection   : {src}")

    if not key:
        print("Status          : WAITING_FOR_KEY (Placeholder detected or key unconfigured)")
        if check_only:
            print("Check complete. No live API call was made.")
            sys.exit(0)
        else:
            print("\nInstructions:")
            print("1. Open /home/soniya/noxim/.env in your editor.")
            print("2. Enter your key after GEMINI_API_KEY= (e.g. GEMINI_API_KEY=your_key_here).")
            print("3. Re-run this test script: python3 sentinel/test_gemini.py")
            sys.exit(2)

    print(f"Status          : KEY_CONFIGURED (Length: {len(key)})")
    if check_only:
        print("Check complete (--check-only). No live API call made.")
        sys.exit(0)

    print("\nTesting minimal live Gemini API request (model: gemini-2.5-flash)...")
    ok, msg, lat = test_gemini_request(key, "gemini-2.5-flash")
    if ok:
        print(f"SUCCESS: Received response from Gemini API in {lat:.2f}s: \"{msg}\"")
        sys.exit(0)
    else:
        print(f"gemini-2.5-flash test failed: {msg}")
        print("Attempting fallback to gemini-1.5-flash...")
        ok2, msg2, lat2 = test_gemini_request(key, "gemini-1.5-flash")
        if ok2:
            print(f"SUCCESS with gemini-1.5-flash in {lat2:.2f}s: \"{msg2}\"")
            sys.exit(0)
        else:
            print(f"gemini-1.5-flash test failed: {msg2}")
            sys.exit(1)
