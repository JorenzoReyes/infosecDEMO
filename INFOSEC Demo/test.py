from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import re
import bcrypt

app = Flask(__name__)
app.secret_key = 'secret'

# Connect to the database
def get_db_connection():
    conn = sqlite3.connect('regex.db')
    return conn

# Create the users table with constraints
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,  
            password TEXT NOT NULL  
        )
    ''')
    conn.commit()
    conn.close()

# Function to validate credentials
def is_valid_credentials(username):
    special_char_pattern = re.compile(r'[^a-zA-Z0-9]')
    return not (special_char_pattern.search(username))

# Home route
@app.route('/')
def home():
    if 'username' in session:
        return f'Welcome, {session["username"]}! <a href="/logout">Logout</a>| <a href="/db">DB</a>'  
    return 'Welcome! <a href="/login">Login</a> | <a href="/register">Register</a>'

@app.route('/user')
def user():
    if 'username' in session:
        return f'Welcome, {session["username"]}! <a href="/logout">Logout</a>'
    return 'Welcome! <a href="/login">Login</a> | <a href="/register">Register</a>'

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        
        # Validate credentials
        if not is_valid_credentials(username):
            return 'Special characters are not allowed in username.<br><a href="/register">Go back</a>'
        
        encoded_password = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=15)
        hashed_password = bcrypt.hashpw(encoded_password, salt)

        conn = get_db_connection()
        conn.executescript(f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed_password}')")
        conn.commit()
        return redirect('/login')
    
    return render_template_string('''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Register">
        </form>
    ''')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Encode password to bytes
        
        # Validate credentials
        if not is_valid_credentials(username):
            return 'Special characters are not allowed in username.<br><a href="/login">Go back</a>'

        encoded_password = password.encode('utf-8')
        conn = get_db_connection()
        cursor = conn.execute(f"SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if bcrypt.checkpw(encoded_password, user[2]):
            session['username'] = user[1]
            if user[1] == 'admin':
                return redirect('/')
            else:
                return redirect('/user')
        else:
            return 'Invalid credentials! <a href="/login">Login</a>'
    
    return render_template_string('''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login"> | <a href="/register">Register</a>
        </form>
    ''')

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

# DB route
@app.route('/db')
def db():
    conn = get_db_connection()
    cursor = conn.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return str(users)

if __name__ == '__main__':
    init_db()  # Ensure database and table exist
    app.run(debug=True)
