from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
import hashlib
import os
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Fix CORS properly
CORS(app, 
     origins=["*"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Database setup
def init_db():
    conn = sqlite3.connect('ctf.db', check_same_thread=False)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT NOT NULL,
                  team_id INTEGER)''')
    
    # Teams table
    c.execute('''CREATE TABLE IF NOT EXISTS teams
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE NOT NULL,
                  code TEXT UNIQUE NOT NULL,
                  score INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Challenges table
    c.execute('''CREATE TABLE IF NOT EXISTS challenges
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  category TEXT NOT NULL,
                  difficulty TEXT NOT NULL,
                  points INTEGER NOT NULL,
                  flag TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Submissions table
    c.execute('''CREATE TABLE IF NOT EXISTS submissions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  team_id INTEGER NOT NULL,
                  challenge_id INTEGER NOT NULL,
                  flag TEXT NOT NULL,
                  poc TEXT,
                  description TEXT,
                  status TEXT DEFAULT 'pending',
                  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert admin user if not exists
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', hashlib.sha256('admin'.encode()).hexdigest(), 'admin'))
        print("✅ Admin user created: username='admin', password='admin'")
    except sqlite3.IntegrityError:
        print("ℹ️ Admin user already exists")
    
    # Insert sample challenges if none exist
    try:
        challenge_count = c.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
        if challenge_count == 0:
            sample_challenges = [
                ('Web Exploitation - Login Bypass', 'Find a way to bypass the login mechanism on the target website.', 'web', 'easy', 100, 'FLAG{web_login_bypass_123}'),
                ('Cryptography - Caesar Cipher', 'Decrypt the given ciphertext that was encrypted using a Caesar cipher.', 'crypto', 'easy', 150, 'FLAG{caesar_shift_3}'),
                ('Forensics - Hidden Message', 'Extract the hidden message from the provided image file.', 'forensics', 'medium', 200, 'FLAG{steganography_is_fun}'),
                ('Pwn - Buffer Overflow', 'Exploit the buffer overflow vulnerability in the provided binary.', 'pwn', 'hard', 300, 'FLAG{stack_smashing_101}')
            ]
            
            for challenge in sample_challenges:
                try:
                    c.execute(
                        'INSERT INTO challenges (title, description, category, difficulty, points, flag) VALUES (?, ?, ?, ?, ?, ?)',
                        challenge
                    )
                except sqlite3.IntegrityError:
                    pass
            print("✅ Sample challenges created")
    except Exception as e:
        print(f"⚠️ Error creating challenges: {e}")
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

# Initialize database on startup
print("🚀 Starting CTF Backend...")
init_db()

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('ctf.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        conn = get_db_connection()
        conn.execute('SELECT 1')
        conn.close()
        return jsonify({
            'status': 'healthy', 
            'message': 'CTF API is running',
            'database': 'connected'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(e)}'
        }), 500

# Root endpoint
@app.route('/')
def root():
    return jsonify({
        'message': 'Flag-Frenxy-25 CTF Backend',
        'version': '1.0',
        'status': 'running',
        'endpoints': {
            'health': '/api/health',
            'login': '/api/login',
            'register': '/api/register',
            'challenges': '/api/challenges',
            'teams': '/api/teams'
        }
    })

# Authentication routes
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No JSON data received'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (username, hashlib.sha256(password.encode()).hexdigest())
        ).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['team_id'] = user['team_id']
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role'],
                    'team_id': user['team_id']
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# User registration
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No JSON data received'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                (username, hashlib.sha256(password.encode()).hexdigest(), 'player')
            )
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Registration successful'})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500

# Get current user info
@app.route('/api/user', methods=['GET'])
def get_user():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    team = None
    if user['team_id']:
        team = conn.execute('SELECT * FROM teams WHERE id = ?', (user['team_id'],)).fetchone()
    
    conn.close()
    
    user_data = {
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'team_id': user['team_id']
    }
    
    if team:
        user_data['team'] = {
            'id': team['id'],
            'name': team['name'],
            'code': team['code'],
            'score': team['score']
        }
    
    return jsonify({'success': True, 'user': user_data})

# Team routes
@app.route('/api/teams', methods=['GET'])
def get_teams():
    try:
        conn = get_db_connection()
        teams = conn.execute('SELECT * FROM teams ORDER BY score DESC').fetchall()
        conn.close()
        return jsonify([dict(team) for team in teams])
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error fetching teams: {str(e)}'}), 500

@app.route('/api/teams', methods=['POST'])
def create_team():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No JSON data received'}), 400
            
        team_name = data.get('name')
        
        if not team_name:
            return jsonify({'success': False, 'message': 'Team name required'}), 400
        
        # Generate unique team code
        team_code = str(uuid.uuid4())[:8].upper()
        
        conn = get_db_connection()
        
        try:
            # Create team
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO teams (name, code) VALUES (?, ?)',
                (team_name, team_code)
            )
            team_id = cursor.lastrowid
            
            # Update user's team
            conn.execute(
                'UPDATE users SET team_id = ? WHERE id = ?',
                (team_id, session['user_id'])
            )
            
            conn.commit()
            session['team_id'] = team_id
            
            conn.close()
            return jsonify({'success': True, 'team_id': team_id, 'code': team_code})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'success': False, 'message': 'Team name already exists'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error creating team: {str(e)}'}), 500

@app.route('/api/teams/join', methods=['POST'])
def join_team():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No JSON data received'}), 400
            
        team_code = data.get('code')
        
        if not team_code:
            return jsonify({'success': False, 'message': 'Team code required'}), 400
        
        conn = get_db_connection()
        team = conn.execute('SELECT * FROM teams WHERE code = ?', (team_code,)).fetchone()
        
        if not team:
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid team code'}), 400
        
        # Update user's team
        conn.execute(
            'UPDATE users SET team_id = ? WHERE id = ?',
            (team['id'], session['user_id'])
        )
        conn.commit()
        conn.close()
        
        session['team_id'] = team['id']
        return jsonify({'success': True, 'team_id': team['id']})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error joining team: {str(e)}'}), 500

# Challenge routes
@app.route('/api/challenges', methods=['GET'])
def get_challenges():
    try:
        conn = get_db_connection()
        challenges = conn.execute('SELECT * FROM challenges').fetchall()
        conn.close()
        return jsonify([dict(challenge) for challenge in challenges])
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error fetching challenges: {str(e)}'}), 500

# Submission routes
@app.route('/api/submissions', methods=['POST'])
def submit_flag():
    if 'user_id' not in session or not session.get('team_id'):
        return jsonify({'success': False, 'message': 'Not authenticated or not in a team'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No JSON data received'}), 400
            
        challenge_id = data.get('challenge_id')
        flag = data.get('flag')
        poc = data.get('poc')
        description = data.get('description')
        
        if not all([challenge_id, flag, poc, description]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        conn = get_db_connection()
        
        # Check if challenge exists and flag is correct
        challenge = conn.execute(
            'SELECT * FROM challenges WHERE id = ? AND flag = ?',
            (challenge_id, flag)
        ).fetchone()
        
        if not challenge:
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid flag'}), 400
        
        # Check if already submitted
        existing = conn.execute(
            'SELECT * FROM submissions WHERE team_id = ? AND challenge_id = ? AND status = "accepted"',
            (session['team_id'], challenge_id)
        ).fetchone()
        
        if existing:
            conn.close()
            return jsonify({'success': False, 'message': 'Challenge already solved'}), 400
        
        # Create submission
        conn.execute(
            'INSERT INTO submissions (team_id, challenge_id, flag, poc, description) VALUES (?, ?, ?, ?, ?)',
            (session['team_id'], challenge_id, flag, poc, description)
        )
        
        # Auto-accept for demo
        conn.execute(
            'UPDATE teams SET score = score + ? WHERE id = ?',
            (challenge['points'], session['team_id'])
        )
        
        conn.execute(
            'UPDATE submissions SET status = "accepted" WHERE team_id = ? AND challenge_id = ?',
            (session['team_id'], challenge_id)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Flag submitted successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error submitting flag: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    print(f"🌐 Starting server on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=debug)
