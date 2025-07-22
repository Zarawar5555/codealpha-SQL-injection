from flask import Flask, request
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

AES_KEY = get_random_bytes(32)
AES_IV = get_random_bytes(16)

def encrypt_password(password):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = password + ' ' * (16 - len(password) % 16)
    encrypted = cipher.encrypt(padded.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')
def decrypt_password(encrypted_base64):
    encrypted = base64.b64decode(encrypted_base64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(encrypted).decode('utf-8').strip()
    return decrypted
def init_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    ''')
    conn.close()

@app.route('/')
def home():
    return '<h2> Secure login system is up and working!</h2>'

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        capability = request.form['capability']

        if capability != 'SECURE123':
            return '<h3> Invalid capability code</h3>'

        bad_keywords = ['--', ';', 'DROP', 'SELECT', 'INSERT', 'DELETE', 'OR 1=1']
        for word in bad_keywords:
            if word.lower() in username.lower() or word.lower() in password.lower():
                return '<h3> SQL Injection Attempt Blocked</h3>'

        encrypted_pw = encrypt_password(password)

        conn = sqlite3.connect('users.db')
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, encrypted_pw))
        conn.commit()
        conn.close()

        return '<h3> Signup successful! Password encrypted and stored.</h3>'

    return '''
        <form method="POST">
            <label>Username:</label><br>
            <input name="username"><br>
            <label>Password:</label><br>
            <input type="password" name="password"><br>
            <label>Capability Code:</label><br>
            <input name="capability"><br><br>
            <input type="submit" value="Sign Up">
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        capability = request.form['capability']

        if capability != 'SECURE123':
            return '<h3> Invalid capability code</h3>'

        bad_keywords = ['--', ';', 'DROP', 'SELECT', 'INSERT', 'DELETE', 'OR 1=1']
        for word in bad_keywords:
            if word.lower() in username.lower() or word.lower() in password_input.lower():
                return '<h3> SQL Injection Attempt Blocked</h3>'

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            return '<h3> User not found</h3>'

        decrypted = decrypt_password(result[0])
        if decrypted == password_input:
            return '<h3> Login successful</h3>'
        else:
            return '<h3> Incorrect password</h3>'

    return '''
        <form method="POST">
            <label>Username:</label><br>
            <input name="username"><br>
            <label>Password:</label><br>
            <input type="password" name="password"><br>
            <label>Capability Code:</label><br>
            <input name="capability"><br><br>
            <input type="submit" value="Login">
        </form>
    '''

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=80)
