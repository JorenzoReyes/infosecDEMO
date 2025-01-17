from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import re

app = Flask(__name__)
app.secret_key = 'secret'

# Connect to the database
def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn

# Create the users table
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
        conn = get_db_connection()

        #vulnerable to: testuser' , 'password'); DROP TABLE users;-- 
        
        conn.executescript(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        conn.commit()
        conn.close()
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
        password = request.form['password']
        conn = get_db_connection()
        
        #vulnerable to: ' OR '1'='1, test' OR '1'='1, test'--;

        query = conn.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        user = query.fetchone()
        conn.close()

        if user:
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