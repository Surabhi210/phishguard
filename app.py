from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib
import re
import os
import requests
import base64
from dotenv import load_dotenv
import os

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

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

def query_vt(endpoint, method="GET", data=None, files=None):
    if not VT_API_KEY:
        return None
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    try:
        if method == "POST":
            res = requests.post(url, headers=headers, data=data, files=files)
        else:
            res = requests.get(url, headers=headers)
        return res.json() if res.status_code == 200 else None
    except Exception as e:
        print(f"VirusTotal query error on {endpoint}: {e}")
        return None

def scan_url_virustotal(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    res = query_vt(f"urls/{url_id}")
    if not res:
        query_vt("urls", method="POST", data={"url": url})
        return {"status": "Unknown URL", "malicious": 0, "harmless": 0}
    stats = res["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    if malicious == 0 and harmless == 0:
        status = "Unknown URL"
    else:
        status = "Malicious" if malicious > 0 else "Safe"
    return {
        "status": status,
        "malicious": malicious,
        "harmless": harmless
    }

def scan_file_hash_virustotal(sha256, filename, file_size, file_bytes):
    res = query_vt(f"files/{sha256}")
    if not res:
        if file_size < 32 * 1024 * 1024:
            query_vt("files", method="POST", files={"file": (filename, file_bytes)})
            return {"status": "Queued", "filename": filename, "size": file_size, "hash": sha256, "malicious": 0, "harmless": 0}
        return {"status": "Unknown", "filename": filename, "size": file_size, "hash": sha256, "malicious": 0, "harmless": 0}
    stats = res["data"]["attributes"]["last_analysis_stats"]
    return {
        "status": "Malicious" if stats.get("malicious", 0) > 0 else "Safe",
        "filename": filename,
        "size": file_size,
        "hash": sha256,
        "malicious": stats.get("malicious", 0),
        "harmless": stats.get("harmless", 0),
        "type_description": res["data"]["attributes"].get("type_description", "Unknown")
    }

def check_domain_reputation(domain):
    res = query_vt(f"domains/{domain}")
    if not res:
        return {"status": "Unknown Domain", "domain": domain, "malicious": 0, "harmless": 0}
    stats = res["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    if malicious == 0 and harmless == 0:
        status = "Unknown Domain"
    else:
        status = "Malicious" if malicious > 0 else "Safe"
    return {
        "status": status,
        "domain": domain,
        "malicious": malicious,
        "harmless": harmless
    }

@app.route("/")
def index_page():
    return send_from_directory(BASE_DIR, "index.html")

# ── FIX: Handle OPTIONS preflight requests (CORS) ──
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        from flask import Response
        res = Response()
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
        res.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return res

@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if model is None or vectorizer is None:
        return jsonify({
            "error": "ML processing components not found on the server. Look at the Python console terminal trace."
        }), 500

    try:
        sender = ""
        subject = ""
        body = ""
        attachment = None

        if request.content_type and "multipart/form-data" in request.content_type:
            sender = request.form.get("sender", "").strip()
            subject = request.form.get("subject", "").strip()
            body = request.form.get("body", "").strip()
            attachment = request.files.get("attachment")
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

        # Handle attachment scan if present
        attachment_result = None
        if attachment and attachment.filename:
            import hashlib
            filename = attachment.filename
            file_bytes = attachment.read()
            file_size = len(file_bytes)
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            attachment_result = scan_file_hash_virustotal(sha256_hash, filename, file_size, file_bytes)

        if not cleaned and not attachment_result and not sender_reputation:
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

        threat_score  = phish_prob_float * 65
        threat_score += min(len(found_keywords) * 3, 20)
        threat_score += min(len(unique_urls) * 3, 10)
        threat_score += min(len(found_spoofs) * 5, 10)
        
        # VirusTotal threat indicators check
        vt_malicious_detected = False
        for vt_u in vt_results:
            if vt_u["status"] == "Malicious":
                vt_malicious_detected = True
                break

        if attachment_result and attachment_result["status"] == "Malicious":
            vt_malicious_detected = True

        if sender_reputation and sender_reputation["status"] == "Malicious":
            vt_malicious_detected = True

        if vt_malicious_detected:
            threat_score += 50
            prediction = 1  # Force prediction if VT reports high-confidence malicious indicators

        threat_score  = max(5, min(int(round(threat_score)), 95))

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
            "virus_total_attachment": attachment_result,
            "sender_reputation": sender_reputation
        })

    except Exception as e:
        print(f"!!! Error: {e}")
        return jsonify({"error": f"Internal execution crash: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)