from flask import Flask, request, jsonify, session
from flask_cors import CORS
import os
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-123')
CORS(app, supports_credentials=True)

# Simple in-memory database (replace with real DB in production)
users_db = {}
teams_db = {}

@app.route('/')
def home():
    return jsonify({"message": "Server is running!", "status": "success"})

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"})
    
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        team = data.get('team', 'default')
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
            
        if username in users_db:
            return jsonify({"error": "Username already exists"}), 400
            
        # Store user
        users_db[username] = {
            'password': password,  # In production, hash this!
            'team': team,
            'created_at': '2024-01-01'
        }
        
        # Initialize team if not exists
        if team not in teams_db:
            teams_db[team] = []
        
        teams_db[team].append(username)
        
        session['user'] = username
        session['team'] = team
        
        return jsonify({
            "status": "success", 
            "message": "Registration successful",
            "user": username,
            "team": team
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"})
    
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
            
        user = users_db.get(username)
        if not user or user['password'] != password:
            return jsonify({"error": "Invalid credentials"}), 401
            
        session['user'] = username
        session['team'] = user['team']
        
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "user": username,
            "team": user['team']
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out"})

@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    user = session.get('user')
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
        
    user_data = users_db.get(user, {})
    return jsonify({
        "status": "success",
        "user": user,
        "team": user_data.get('team', 'null'),
        "dashboard_data": f"Welcome to your dashboard, {user}!"
    })

@app.route('/api/user', methods=['GET'])
def get_user():
    user = session.get('user')
    if user:
        user_data = users_db.get(user, {})
        return jsonify({
            "authenticated": True,
            "user": user,
            "team": user_data.get('team', 'null')
        })
    return jsonify({"authenticated": False})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
