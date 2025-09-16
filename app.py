from flask import Flask, render_template, request, session, redirect, url_for, flash
import sqlite3
from datetime import datetime, timedelta
import requests  # For IP geolocation
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # More secure random key

# Initialize SQLite DB with password field
def init_db():
    with sqlite3.connect('competition.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     email TEXT UNIQUE, 
                     password TEXT,
                     points INTEGER DEFAULT 0,
                     last_offer TIMESTAMP, 
                     referrals INTEGER DEFAULT 0, 
                     ip TEXT, 
                     user_agent TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS referrals
                     (new_user INTEGER, ref_id INTEGER, FOREIGN KEY(new_user) REFERENCES users(id))''')
        conn.commit()

init_db()

def get_db_connection():
    conn = sqlite3.connect('competition.db')
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

# Password hashing function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT email, points, referrals FROM users WHERE id=?", (session['user_id'],))
            user = c.fetchone()

        if not user:  # Safety check: if user not found, clear session and redirect
            session.clear()
            return redirect(url_for('login'))

        return render_template('dashboard.html', user_email=user['email'], points=user['points'], referrals=user['referrals'])
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return render_template('error.html', error="Database error occurred")

# NEW: Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', 'Unknown')
        
        # Basic validation
        if not email or not password:
            return render_template('register.html', error="Email and password are required")
            
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")
            
        if len(password) < 6:
            return render_template('register.html', error="Password must be at least 6 characters")
        
        # Geo check for SA (skip local testing)
        if not ip.startswith('127.0.') and not ip.startswith('::1'):
            try:
                geo_response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('country_code') != 'ZA':
                        return render_template('register.html', error="Sorry, this competition is only available in South Africa.")
            except:
                pass  # Fail open if API fails

        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # Check if email already exists
                c.execute("SELECT id FROM users WHERE email=?", (email,))
                if c.fetchone():
                    return render_template('register.html', error="Email already registered")
                
                # Hash password and create user
                hashed_password = hash_password(password)
                c.execute("INSERT INTO users (email, password, ip, user_agent) VALUES (?, ?, ?, ?)", 
                         (email, hashed_password, ip, ua))
                conn.commit()
                new_id = c.lastrowid
                
                if new_id:
                    session['user_id'] = new_id
                    # Handle pending referral if any
                    pending_ref = session.pop('pending_ref', None)
                    if pending_ref:
                        try:
                            ref_id = int(pending_ref)
                            c.execute("INSERT OR IGNORE INTO referrals (new_user, ref_id) VALUES (?, ?)",
                                      (new_id, ref_id))
                            conn.commit()
                            print(f"New user referral inserted: new_user={new_id}, ref_id={ref_id}")
                        except ValueError:
                            print("Invalid ref_id, skipping")
                    
                    return redirect(url_for('home'))
                else:
                    return render_template('register.html', error="Failed to create account. Try again.")
                    
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return render_template('register.html', error="Database error occurred. Please try again.")

    return render_template('register.html', error=None)

# UPDATED: Login route to use email and password
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', 'Unknown')

        # Basic validation
        if not email or not password:
            return render_template('login.html', error="Email and password are required")

        # Geo check for SA (skip local testing)
        if not ip.startswith('127.0.') and not ip.startswith('::1'):
            try:
                geo_response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('country_code') != 'ZA':
                        return render_template('login.html', error="Sorry, this competition is only available in South Africa.")
            except:
                pass  # Fail open if API fails

        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                # Check email and password
                hashed_password = hash_password(password)
                c.execute("SELECT id, ip, user_agent FROM users WHERE email=? AND password=?", 
                         (email, hashed_password))
                user_row = c.fetchone()

                if user_row:
                    existing_id, existing_ip, existing_ua = user_row['id'], user_row['ip'], user_row['user_agent']
                    # Check IP and UA for one account per user (allow minor UA variations, but strict IP)
                    if existing_ip != ip or existing_ua != ua:
                        return render_template('login.html', error="Suspicious login attempt detected. Please use the same device and location. One account per user only.")
                    
                    session['user_id'] = existing_id
                    # Handle pending referral after user creation
                    pending_ref = session.pop('pending_ref', None)
                    if pending_ref:
                        try:
                            ref_id = int(pending_ref)
                            c.execute("INSERT OR IGNORE INTO referrals (new_user, ref_id) VALUES (?, ?)",
                                      (session['user_id'], ref_id))
                            conn.commit()
                            print(f"Referral inserted: new_user={session['user_id']}, ref_id={ref_id}")
                        except ValueError:
                            print("Invalid ref_id, skipping")
                    return redirect(url_for('home'))
                else:
                    return render_template('login.html', error="Invalid email or password")
                    
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return render_template('login.html', error="Database error occurred. Please try again.")

    return render_template('login.html', error=None)

@app.route('/offer_wall')
def offer_wall():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT last_offer FROM users WHERE id=?", (session['user_id'],))
            result = c.fetchone()
            last_offer = result['last_offer'] if result else None

        if last_offer and datetime.now() - datetime.fromisoformat(last_offer) < timedelta(hours=1):
            remaining_minutes = int((datetime.fromisoformat(last_offer) + timedelta(hours=2) - datetime.now()).total_seconds() / 60)
            return render_template('cooldown.html', remaining=remaining_minutes)

        # Replace with your CPAlead offerwall URL, passing user_id as subid
        offerwall_url = "http:localhost:8080?sub={}".format(session['user_id'])
        return render_template('offer_wall.html', offerwall_url=offerwall_url)

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return redirect(url_for('home'))

@app.route('/postback', methods=['POST'])
def postback():
    # Add some basic authentication/validation here
    subid = request.form.get('subid')  # User ID from CPAlead
    earned = int(request.form.get('virtual_currency', 10))  # Points earned

    if subid and earned:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("UPDATE users SET points = points + ?, last_offer = ? WHERE id=?",
                          (earned, datetime.now().isoformat(), subid))
                # Credit referrer if exists
                c.execute("SELECT ref_id FROM referrals WHERE new_user=?", (subid,))
                ref = c.fetchone()
                if ref:
                    c.execute("UPDATE users SET points = points + 10, referrals = referrals + 1 WHERE id=?", (ref['ref_id'],))
                conn.commit()
                print(f"Credited {earned} points to user {subid}")
        except sqlite3.Error as e:
            print(f"Database error in postback: {e}")

    return "OK"

@app.route('/refer')
def refer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Use your deployed URL later (e.g., https://your-site.onrender.com)
    base_url = request.host_url.rstrip('/')
    ref_link = f"{base_url}/signup?ref={session['user_id']}"
    return render_template('refer.html', ref_link=ref_link)

@app.route('/signup')
def signup():
    ref_id = request.args.get('ref')
    if 'user_id' not in session:
        if ref_id:
            session['pending_ref'] = ref_id  # Store temporarily
        return redirect(url_for('register'))  # Changed from login to register

    # If already logged in (edge case), insert and go home
    if ref_id:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                try:
                    ref_id_int = int(ref_id)
                    c.execute("INSERT OR IGNORE INTO referrals (new_user, ref_id) VALUES (?, ?)",
                              (session['user_id'], ref_id_int))
                    conn.commit()
                    print(f"Direct referral insert: new_user={session['user_id']}, ref_id={ref_id_int}")
                except ValueError:
                    print("Invalid ref_id, skipping")
        except sqlite3.Error as e:
            print(f"Database error in signup: {e}")

    return redirect(url_for('home'))

# FIXED: Corrected the route and function name
@app.route('/leaderborad')
def leaderborad():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT email, points, referrals FROM users ORDER BY points DESC LIMIT 10")
            top10 = c.fetchall()
        return render_template('leaderborad.html', top10=top10)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return render_template('leaderborsd.html', top10=[])

@app.route('/withdrawal')
def withdrawal():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()

            # Get user's current points and rank
            c.execute("""
                SELECT u.id, u.points,
                (SELECT COUNT(*) + 1 FROM users u2 WHERE u2.points > u.points) as rank
                FROM users u WHERE u.id=?
            """, (session['user_id'],))
            user_data = c.fetchone()

            if not user_data:
                session.clear()
                return redirect(url_for('login'))

            user_rank = user_data['rank']
            user_points = user_data['points']
            is_top_ten = user_rank <= 10

            # Check if it's end of September (after Sept 21)
            today = datetime.now()
            is_end_of_september = today.month == 9 and today.day >= 21

            # Calculate days remaining until Sept 21
            if today.month < 9 or (today.month == 9 and today.day < 21):
                target_date = datetime(today.year, 9, 21)
                days_remaining = (target_date - today).days
            else:
                days_remaining = 0

            # Determine prize amount based on rank (example values)
            prize_amounts = {
                1: 1000, 2: 800, 3: 600, 4: 400, 5: 300,
                6: 200, 7: 150, 8: 120, 9: 100, 10: 100
            }
            prize_amount = prize_amounts.get(user_rank, 0) if is_top_ten else 0

        return render_template('withdrawal.html',
                             is_top_ten=is_top_ten,
                             is_end_of_september=is_end_of_september,
                             days_remaining=days_remaining,
                             user_rank=user_rank,
                             user_points=user_points,
                             prize_amount=prize_amount)

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return render_template('error.html', error="Database error occurred")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
