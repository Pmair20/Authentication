import base64
from base64 import b64encode, b64decode
from flask import Flask, request, render_template, redirect
import json
import hashlib
import bcrypt
import requests

app = Flask(__name__)
app.secret_key = 'SecretiveAuthbyBamaBoy'
UserID = {}
def load_users():
    global UserID
    with open('UserID.json', 'r') as file:
        UserID = json.load(file)
def save_users():
    with open('UserID.json', 'w') as file:
        json.dump(UserID, file, indent=4)
def authenticate_user(username, password):
    if username in UserID:
        stored_password = UserID[username]['hashed_password']
        salt = UserID[username]['salt']
        hashed_password = hashlib.md5(password.encode('utf-8'), salt.encode('utf-8'))
        return stored_password == hashed_password.decode('utf-8')
    return False
def encode_ID(username, password):
    credentials = f"{username}:{password}"
    encoded_ID = b64encode(credentials.encode('utf-8')).decode('utf-8')
    return f'Basic {encoded_ID}'
def decode_ID(authorization_header):
    encoded_ID = authorization_header.split(' ')[1]
    credentials = b64decode(encoded_ID).decode('utf-8')
    username, password = credentials.split(':')
    return username, password
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in UserID:
            error = "Username already exists, Pick another one"
        else:
            salt = bcrypt.gensalt()
            hashed_password = hashlib.md5(password.encode('utf-8'), salt)
            UserID[username] = {'hashed_password': hashed_password.decode('utf-8'), 'salt': salt.decode('utf-8')}
            save_users()
            return 'Account created successfully, go back and sign in again'
    return render_template('signup.html', error=error)
@app.route('/checkAuth', methods=['GET', 'POST'])
def check_auth():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')
        if authenticate_user(username, password):
            return "Ok"
        else:
            return "Invalid credentials", 401
    else:
        return "Authorization header not found", 401
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        credentials = encode_ID(username, password)
        headers = {'Authorization': credentials}
        response = requests.post(url='http://localhost:8080/checkAuth', headers=headers)
        if response.status_code == 200:
            return redirect('/main')
        else:
            error = "Invalid credentials, Please enter it correctly"
    return render_template('login.html', error=error)
if __name__ == '__main__':
    load_users()
    app.run(debug=True, port=8080)
