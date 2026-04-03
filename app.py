import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import datetime

app = Flask(__name__)
CORS(app)

# --- MONGODB CONNECTION ---
# Render ke Environment Variables mein MONGO_URI zaroor daalein
MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['phishguard_db']
users_collection = db['users']

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
    if any(x in url for x in ["bit.ly", "t.co", "tinyurl"]):
        score += 30
        flags.append("Shortened link used")
    
    status = "Safe"
    if score > 50: status = "Phishing"
    elif score > 20: status = "Suspicious"
    return {"score": min(score, 99), "status": status, "flags": flags}

@app.route('/')
def home():
    return "PhishGuard Backend is Live and Connected to MongoDB!"

# --- SIGNUP ROUTE ---
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
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

# --- LOGIN ROUTE ---
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        user = users_collection.find_one({"email": email, "password": password})
        if user:
            return jsonify({"message": "Login successful!"}), 200
        else:
            return jsonify({"message": "Invalid email or password"}), 401
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    result = analyze_url(data.get('url', ''))
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
