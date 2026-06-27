from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
import os

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
        data = request.json or {}
        sender  = data.get("sender",  "").strip()
        subject = data.get("subject", "").strip()
        body    = data.get("body",    "").strip()

        combined_raw = f"Sender: {sender} Subject: {subject} Body: {body}"
        cleaned = clean_text(combined_raw)

        if not cleaned:
            return jsonify({
                "prediction": 0, "threat_score": 0,
                "phish_prob": 0, "safe_prob": 100,
                "keywords": [], "urls": [], "spoofed": []
            })

        vec        = vectorizer.transform([cleaned])
        prediction = int(model.predict(vec)[0])
        probs      = model.predict_proba(vec)[0]

        phish_prob_float = float(probs[1])
        safe_prob_float  = float(probs[0])

        all_lower      = combined_raw.lower()
        found_keywords = [w for w in suspicious_keywords if w in all_lower]
        urls_found     = re.findall(r'(https?://\S+|www\.\S+)', combined_raw)

        found_spoofs = []
        for d in SPOOFED_DOMAINS:
            if d in all_lower:
                found_spoofs.append(d)
        found_spoofs = list(set(found_spoofs))

        threat_score  = phish_prob_float * 65
        threat_score += min(len(found_keywords) * 3, 20)
        threat_score += min(len(urls_found) * 3, 10)
        threat_score += min(len(found_spoofs) * 5, 10)
        threat_score  = min(int(round(threat_score)), 100)

        return jsonify({
            "prediction":   prediction,
            "threat_score": threat_score,
            "phish_prob":   int(round(phish_prob_float * 100)),
            "safe_prob":    int(round(safe_prob_float  * 100)),
            "keywords":     found_keywords,
            "urls":         urls_found,
            "spoofed":      found_spoofs
        })

    except Exception as e:
        print(f"!!! Error: {e}")
        return jsonify({"error": f"Internal execution crash: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)