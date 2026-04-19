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
    score = 0
    flags = []
    url = url.lower()

    if not url.startswith("https"):
        score += 25
        flags.append("Insecure connection (No HTTPS)")
    if len(url) > 75:
        score += 20
        flags.append("Suspiciously long URL")
    if any(x in url for x in ["bit.ly", "t.co", "tinyurl", "is.gd"]):
        score += 30
        flags.append("Shortened link detected")
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 40
        flags.append("Direct IP address used")
    
    keywords = ["login", "verify", "bank", "secure", "account", "update", "password"]
    found = [w for w in keywords if w in url]
    if found:
        score += 20
        flags.append(f"Suspicious keywords: {', '.join(found)}")

    status = "Safe"
    if score >= 50: status = "Phishing"
    elif score >= 25: status = "Suspicious"
    
    return {"score": min(score, 100), "status": status, "flags": flags}

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '')
    result = analyze_url(url)
    return jsonify(result)

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User exists"}), 400
    users_collection.insert_one({"email": email, "password": password, "created_at": datetime.datetime.now()})
    return jsonify({"message": "Success"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = users_collection.find_one({"email": data.get('email'), "password": data.get('password')})
    return jsonify({"message": "Login successful!"}) if user else (jsonify({"message": "Invalid"}), 401)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
