const API_BASE = window.location.hostname === 'localhost' 
    ? 'http://localhost:10000' 
    : 'https://your-backend-url.onrender.com';

let currentUser = null;

// DOM Content Loaded
document.addEventListener('DOMContentLoaded', function() {
    checkAuthStatus();
    setupEventListeners();
});

function setupEventListeners() {
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('registerForm').addEventListener('submit', handleRegister);
}

async function checkAuthStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/user`, {
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.authenticated) {
            currentUser = data.user;
            showDashboard(data.user, data.team);
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        username: formData.get('username'),
        password: formData.get('password')
    };

    try {
        const response = await fetch(`${API_BASE}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(data)
        });

        const result = await response.json();
        
        if (response.ok) {
            showMessage('Login successful!', 'success');
            currentUser = result.user;
            showDashboard(result.user, result.team);
        } else {
            showMessage(result.error || 'Login failed', 'error');
        }
    } catch (error) {
        showMessage('Network error: ' + error.message, 'error');
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        username: formData.get('username'),
        password: formData.get('password'),
        team: formData.get('team') || 'default'
    };

    try {
        const response = await fetch(`${API_BASE}/api/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(data)
        });

        const result = await response.json();
        
        if (response.ok) {
            showMessage('Registration successful!', 'success');
            currentUser = result.user;
            showDashboard(result.user, result.team);
        } else {
            showMessage(result.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showMessage('Network error: ' + error.message, 'error');
    }
}

async function logout() {
    try {
        await fetch(`${API_BASE}/api/logout`, {
            method: 'POST',
            credentials: 'include'
        });
        currentUser = null;
        showAuth();
        showMessage('Logged out successfully', 'success');
    } catch (error) {
        showMessage('Logout error: ' + error.message, 'error');
    }
}

function showDashboard(user, team) {
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    document.getElementById('user-name').textContent = user;
    document.getElementById('user-team').textContent = team;
    document.getElementById('dashboard-data').textContent = `Welcome to your dashboard, ${user}!`;
    
    // Load additional dashboard data
    loadDashboardData();
}

async function loadDashboardData() {
    try {
        const response = await fetch(`${API_BASE}/api/dashboard`, {
            credentials: 'include'
        });
        const data = await response.json();
        
        if (response.ok) {
            document.getElementById('dashboard-data').textContent = data.dashboard_data;
        }
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

function showAuth() {
    document.getElementById('auth-section').style.display = 'block';
    document.getElementById('dashboard').style.display = 'none';
    showLogin();
}

function showLogin() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
}

function showRegister() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

function showMessage(message, type) {
    const messageEl = document.getElementById('message');
    messageEl.textContent = message;
    messageEl.className = `message ${type}`;
    messageEl.style.display = 'block';
    
    setTimeout(() => {
        messageEl.style.display = 'none';
    }, 5000);
}
