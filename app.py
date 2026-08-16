from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib
import re
import os
import requests
import base64
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
    print("\n[-] WARNING: VT_API_KEY is not configured or uses placeholder value.")
    print("    VirusTotal file/URL/domain scans will be bypassed/skipped with error details.\n")
else:
    print("\n[+] VT_API_KEY detected. VirusTotal scans enabled.\n")

app = Flask(__name__)

# ── FIX: Allow ALL origins (fixes "Failed to fetch" from Live Server) ──
CORS(app, resources={r"/*": {"origins": "*"}})

# Declare global variables explicitly so they are defined even if loading fails
model = None
vectorizer = None

# ── FIX: Use absolute path so .pkl files are always found ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print(f"[*] App directory: {BASE_DIR}")

# ── LOAD THE PIPELINE MODELS ──
try:
    model = joblib.load(os.path.join(BASE_DIR, "spam_model.pkl"))
    vectorizer = joblib.load(os.path.join(BASE_DIR, "tfidf_vectorizer.pkl"))
    print("[+] Both backend pipeline components loaded successfully!")
except Exception as e:
    print(f"\n!!! CRITICAL PIPELINE MODEL LOADING FAILURE !!!")
    print(f"Reason: {str(e)}")
    print(f"Please confirm that 'spam_model.pkl' and 'tfidf_vectorizer.pkl' reside inside:")
    print(f"👉 {BASE_DIR}\n")

# ── INDICATOR DICTIONARIES FOR METRICS GENERATION ──
suspicious_keywords = [
    "urgent", "verify", "account", "suspended", "click", "login",
    "password", "bank", "limited", "confirm", "update", "security",
    "reward", "winner", "free", "claim", "offer", "lottery",
    "invoice", "payment", "reset", "immediately", "action required",
    "otp", "gift", "prize", "congratulations", "expire", "unusual activity",
    "deactivated", "validate", "credentials", "wire transfer", "bitcoin"
]

SPOOFED_DOMAINS = [
    "secure-paypal", "paypal-login", "apple-id", "google-security",
    "amazon-verify", "netflix-account", "microsoft-security",
    "support-", "-support", "verify-", "-verify", "login-", "-login",
    "secure-", "-secure", "account-", "-account"
]

def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " ", text)
    text = re.sub(r"\S+@\S+", " ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def is_valid_vt_response(res):
    return res and isinstance(res, dict) and "data" in res

def query_vt(endpoint, method="GET", data=None, files=None):
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"error": "missing_api_key"}
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    try:
        if method == "POST":
            res = requests.post(url, headers=headers, data=data, files=files)
        else:
            res = requests.get(url, headers=headers)

        if res.status_code == 200:
            return res.json()
        elif res.status_code in [401, 403]:
            return {"error": "invalid_api_key"}
        else:
            return {"error": f"http_{res.status_code}"}
    except Exception as e:
        print(f"VirusTotal query error on {endpoint}: {e}")
        return {"error": "connection_error"}

def parse_vt_stats(stats, default_status="Safe"):
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + harmless + suspicious + undetected

    if total == 0:
        return default_status, malicious, harmless

    malicious_ratio = malicious / total

    # require either a decent absolute count OR a meaningful share
    # of vendors flagging it — one stray vendor shouldn't decide this
    if malicious >= 3 or malicious_ratio > 0.05:
        status = "Malicious"
    elif harmless > 0:
        status = "Safe"
    else:
        status = default_status

    return status, malicious, harmless

def scan_url_virustotal(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    res = query_vt(f"urls/{url_id}")

    if not is_valid_vt_response(res):
        if isinstance(res, dict) and res.get("error") in ["missing_api_key", "invalid_api_key"]:
            return {
                "status": "Skipped (API Key Error)",
                "malicious": 0,
                "harmless": 0,
                "message": "VirusTotal API key is missing or invalid. Check your .env file configuration."
            }

        query_vt("urls", method="POST", data={"url": url})
        return {"status": "Unknown URL", "malicious": 0, "harmless": 0}

    stats = res["data"]["attributes"]["last_analysis_stats"]
    status, malicious, harmless = parse_vt_stats(stats, default_status="Unknown URL")
    return {
        "status": status,
        "malicious": malicious,
        "harmless": harmless
    }

def check_domain_reputation(domain):
    res = query_vt(f"domains/{domain}")

    if not is_valid_vt_response(res):
        if isinstance(res, dict) and res.get("error") in ["missing_api_key", "invalid_api_key"]:
            return {
                "status": "Skipped (API Key Error)",
                "domain": domain,
                "malicious": 0,
                "harmless": 0,
                "message": "VirusTotal API key is missing or invalid. Check your .env file configuration."
            }
        return {"status": "Unknown Domain", "domain": domain, "malicious": 0, "harmless": 0}

    stats = res["data"]["attributes"]["last_analysis_stats"]
    status, malicious, harmless = parse_vt_stats(stats, default_status="Unknown Domain")
    return {
        "status": status,
        "domain": domain,
        "malicious": malicious,
        "harmless": harmless
    }

def calculate_threat_score(phish_prob, found_keywords, unique_urls, found_spoofs, vt_results, sender_reputation, base_prediction):
    threat_score = phish_prob * 65
    threat_score += min(len(found_keywords) * 3, 20)
    threat_score += min(len(unique_urls) * 3, 10)
    threat_score += min(len(found_spoofs) * 5, 10)

    # VirusTotal threat indicators check
    vt_malicious_detected = any(vt_u["status"] == "Malicious" for vt_u in vt_results)

    if sender_reputation and sender_reputation["status"] == "Malicious":
        vt_malicious_detected = True

    prediction = base_prediction
    if vt_malicious_detected:
        threat_score += 50
        prediction = 1

    threat_score = max(5, min(int(round(threat_score)), 95))
    return threat_score, prediction

@app.route("/")
def index_page():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    # ── FIX: short-circuit CORS preflight requests ──
    # Because "OPTIONS" is listed explicitly in methods above, Flask routes
    # OPTIONS requests to this view instead of letting flask-cors auto-handle
    # them. Without this early return, the OPTIONS request falls into the
    # try block below (which expects a real POST body) and errors out,
    # causing the browser to reject the preflight and block the real
    # request with a CORS error ("Failed to fetch").
    if request.method == "OPTIONS":
        return "", 200

    if model is None or vectorizer is None:
        return jsonify({
            "error": "ML processing components not found on the server. Look at the Python console terminal trace."
        }), 500

    try:
        sender = ""
        subject = ""
        body = ""

        if request.content_type and "multipart/form-data" in request.content_type:
            sender = request.form.get("sender", "").strip()
            subject = request.form.get("subject", "").strip()
            body = request.form.get("body", "").strip()
        else:
            data = request.json or {}
            sender = data.get("sender", "").strip()
            subject = data.get("subject", "").strip()
            body = data.get("body", "").strip()

        combined_raw = f"Sender: {sender} Subject: {subject} Body: {body}"
        cleaned = clean_text(combined_raw)

        # Handle sender domain reputation check
        sender_reputation = None
        if sender:
            email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender)
            if email_match:
                domain = email_match.group(1).lower().strip()
                sender_reputation = check_domain_reputation(domain)

        if not cleaned and not sender_reputation:
            return jsonify({
                "prediction": 0, "threat_score": 0,
                "phish_prob": 0, "safe_prob": 100,
                "keywords": [], "urls": [], "spoofed": [],
                "virus_total": None, "virus_total_urls": [],
                "virus_total_attachment": None,
                "sender_reputation": None
            })

        prediction = 0
        phish_prob_float = 0.0
        safe_prob_float = 1.0

        if cleaned:
            vec        = vectorizer.transform([cleaned])
            prediction = int(model.predict(vec)[0])
            probs      = model.predict_proba(vec)[0]
            phish_prob_float = float(probs[1])
            safe_prob_float  = float(probs[0])

        all_lower      = combined_raw.lower()
        found_keywords = [w for w in suspicious_keywords if w in all_lower]
        urls_found     = re.findall(r'(https?://\S+|www\.\S+)', combined_raw)

        # Clean URLs and keep unique ones
        unique_urls = []
        for u in urls_found:
            cleaned_u = u.strip().rstrip(".,;!?)'\"<>")
            if cleaned_u and cleaned_u not in unique_urls:
                unique_urls.append(cleaned_u)

        # Scan unique URLs (up to 3)
        vt_results = []
        for u in unique_urls[:3]:
            res = scan_url_virustotal(u)
            vt_results.append({
                "url": u,
                "status": res["status"],
                "malicious": res["malicious"],
                "harmless": res["harmless"]
            })

        found_spoofs = []
        for d in SPOOFED_DOMAINS:
            if d in all_lower:
                found_spoofs.append(d)
        found_spoofs = list(set(found_spoofs))

        threat_score, prediction = calculate_threat_score(
            phish_prob=phish_prob_float,
            found_keywords=found_keywords,
            unique_urls=unique_urls,
            found_spoofs=found_spoofs,
            vt_results=vt_results,
            sender_reputation=sender_reputation,
            base_prediction=prediction
        )

        return jsonify({
            "prediction": prediction,
            "threat_score": threat_score,
            "phish_prob": int(round(phish_prob_float * 100)),
            "safe_prob": int(round(safe_prob_float * 100)),
            "keywords": found_keywords,
            "urls": unique_urls,
            "spoofed": found_spoofs,
            "virus_total": vt_results[0] if vt_results else None,
            "virus_total_urls": vt_results,
            "virus_total_attachment": None,
            "sender_reputation": sender_reputation
        })

    except Exception as e:
        print(f"!!! Error: {e}")
        return jsonify({"error": f"Internal execution crash: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)