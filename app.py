import os
import re
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)

# --- MONGODB CONNECTION ---
MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['phishguard_db']
users_collection = db['users']

def analyze_url(url):
    """Advanced Heuristic Logic for Accurate Detection"""
    score = 0
    flags = []
    url = url.lower()

    # 1. SSL/Security Check (Phishers avoid HTTPS sometimes)
    if not url.startswith("https"):
        score += 25
        flags.append("Insecure connection (No HTTPS)")

    # 2. Length Check (Phishers use long URLs to hide the real domain)
    if len(url) > 75:
        score += 20
        flags.append("Suspiciously long URL")

    # 3. URL Shortener Check (Commonly used in SMS/Email phishing)
    shorteners = ["bit.ly", "t.co", "tinyurl", "is.gd", "rebrand.ly"]
    if any(x in url for x in shorteners):
        score += 30
        flags.append("Shortened link used to disguise destination")

    # 4. IP Address Detection (CRITICAL: Real sites use names, not numbers)
    # This regex looks for patterns like 192.168.1.1
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, url):
        score += 40
        flags.append("Direct IP address used instead of domain name")

    # 5. Sensitive Keywords Analysis
    # Checking for words that trigger psychological urgency
    keywords = ["login", "verify", "secure", "bank", "update", "password", "account", "signin", "kyc"]
    found_keywords = [word for word in keywords if word in url]
    if found_keywords:
        score += 15
        flags.append(f"Suspicious keywords detected: {', '.join(found_keywords)}")

    # 6. Special Character '@' Check (Used to hide the real domain)
    if "@" in url:
        score += 20
        flags.append("Contains '@' symbol (Redirect tactic)")

    # --- FINAL VERDICT LOGIC ---
    status = "Safe"
    if score >= 50:
        status = "Phishing"
    elif score >= 25:
        status = "Suspicious"
        
    return {
        "score": min(score, 100), 
        "status": status, 
        "flags": flags,
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

@app.route('/')
def home():
    return "PhishGuard Backend is Live and Connected to MongoDB!"

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({"message": "Fill all fields"}), 400
        if users_collection.find_one({"email": email}):
            return jsonify({"message": "User already exists!"}), 400
        users_collection.insert_one({
            "email": email, 
            "password": password, 
            "created_at": datetime.datetime.now()
        })
        return jsonify({"message": "Account created successfully!"}), 201
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user = users_collection.find_one({"email": email, "password": password})
        if user:
            return jsonify({"message": "Login successful!"}), 200
        return jsonify({"message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        url = data.get('url', '')
        if not url:
            return jsonify({"error": "URL is required"}), 400
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
