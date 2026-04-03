import os
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Isse hamara Frontend is Backend se baat kar payega

def analyze_url(url):
    """Simple AI Logic for Link Analysis"""
    score = 0
    flags = []
    url = url.lower()

    if "https" not in url:
        score += 25
        flags.append("Insecure connection (No HTTPS)")
    if len(url) > 75:
        score += 20
        flags.append("Suspiciously long URL")
    if "bit.ly" in url or "t.co" in url or "tinyurl" in url:
        score += 30
        flags.append("Shortened link used to hide destination")
    if "@" in url:
        score += 15
        flags.append("Contains '@' symbol (Common phishing tactic)")
    
    # Final Result logic
    status = "Safe"
    level = "Low"
    if score > 50:
        status = "Phishing"
        level = "High"
    elif score > 20:
        status = "Suspicious"
        level = "Medium"
        
    return {"score": min(score, 99), "status": status, "level": level, "flags": flags}

@app.route('/')
def home():
    return "PhishGuard Backend is Running!"

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target_url = data.get('url', '')
        if not target_url:
            return jsonify({"error": "No URL provided"}), 400
            
        result = analyze_url(target_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
