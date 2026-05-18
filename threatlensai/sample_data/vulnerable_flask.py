from flask import Flask, request, render_template_string
import sqlite3
import subprocess
import os

app = Flask(__name__)
app.secret_key = "mysecretkey123"  # Hardcoded secret key - BAD

DATABASE = "users.db"

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # VULNERABLE: SQL Injection - string formatting in query
    sql = f"SELECT * FROM products WHERE name = '{query}'"
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    
    # VULNERABLE: Server-Side Template Injection (SSTI)
    template = f"<h1>Results for: {query}</h1><p>{results}</p>"
    return render_template_string(template)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    
    # VULNERABLE: Command Injection - user input passed directly to shell
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout

@app.route('/file')
def read_file():
    filename = request.args.get('name', '')
    
    # VULNERABLE: Path Traversal - no path sanitization
    filepath = os.path.join('/var/www/uploads', filename)
    with open(filepath, 'r') as f:
        return f.read()

@app.route('/admin')
def admin():
    # VULNERABLE: No authentication check at all
    return "Admin panel - all users: " + str(get_all_users())

def get_all_users():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM users")  # Returns plaintext passwords
    return cursor.fetchall()

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode enabled in production - BAD
