import sqlite3
from flask import Flask, session, redirect, url_for, request, render_template, flash, jsonify, abort
from datetime import datetime   
import spacy

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'df0331cefc6c2b9a5d0208a726a5d1c0fd37324feba25506'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db_connection()

        # Check if the table exists
        if db.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="users" OR name="email" OR name="keywords"').fetchone() is None:
            with app.open_resource('schema.sql') as f:
                db.executescript(f.read().decode('utf8'))
        else:
            pass
        
        db.commit()


#         # Create the table if it doesn't exist
#         if not table_exists:
#             with app.open_resource('schema.sql') as f:
#                 db.executescript(f.read().decode('utf8'))

#             db.execute("""
#                 CREATE TABLE users IF NOT EXISTS (
#                     id INTEGER PRIMARY KEY AUTOINCREMENT,
#                     username TEXT NOT NULL,
#                     email TEXT NOT NULL,
#                     password TEXT NOT NULL,
#                     timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
#                     is_admin BOOLEAN DEFAULT FALSE
#                 );
#             """)
            
#             db.execute('''
#                 CREATE TABLE IF NOT EXISTS email(
#                     id INTEGER PRIMARY KEY AUTOINCREMENT,
#                     sender TEXT NOT NULL,
#                     recipient TEXT NOT NULL,
#                     subject TEXT NOT NULL,
#                     body TEXT NOT NULL,
#                     time TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
#                     threat INTEGER DEFAULT 0
#                 );
#             ''')
            
#             db.execute('''
#                     CREATE TABLE IF NOT EXISTS keywords(
#                         id INTEGER PRIMARY KEY AUTOINCREMENT,
#                         keyword TEXT NOT NULL
#                     );
#                 ''')
            
#             db.commit()

@app.before_request
def before_request():
    init_db()

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/signup', methods=['POST'])
def signup():
    # get the form data
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    # connect to the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    # insert the user data into the database
    cur.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, password))
    conn.commit()

    # close the database connection
    cur.close()
    conn.close()

    # set the session variables
    session['username'] = username
    session['email'] = email
    session['role'] = 0

    # redirect the user to the index page
    return redirect(url_for('inbox', username=username))

@app.route('/login', methods=['POST'])
def login():
    # get the form data
    email = request.form['email']
    password = request.form['password']

    # print('email:', email)
    # print('password:', password)

    # connect to the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    # check if the user exists in the database
    user = conn.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password)).fetchone()
    
    # close the database connection
    cur.close()
    conn.close()
    # if the user exists, set the session variables and redirect the user to the appropriate page
    if user:
        session['username'] = user[1]
        session['email'] = user[2]
        session['role'] = user[5]
        if session.get('role') == 1:
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('inbox'))
    else:
        # if the user does not exist, redirect them to the index page
        return redirect(url_for('index'))
    
@app.route('/admin', methods=['GET'])
def admin():
    # check if the user is an admin
    if session.get('role') == 1:
        return render_template('dashboard.html')
    else:
        # if the user is not an admin, redirect to the index page
        return redirect(url_for('index'))
    
@app.route('/logout', methods=['GET'])
def logout():
    # remove the session variables
    session.pop('username', None)
    session.pop('role', None)

    # redirect the user to the index page
    return redirect(url_for('index'))

@app.route('/inbox')
def inbox():
    # connect to the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    
    # fetch all the emails from the database
    cur.execute('SELECT * FROM email where recipient = ? OR sender = ? ORDER BY time DESC', (session.get('email'), session.get('email')))
    emails = cur.fetchall()
    # print(emails)
    # close the database connection
    cur.close()
    conn.close()

    return render_template('inbox.html', emails=emails)

@app.route('/inbox/<int:email_id>')
def email_detail(email_id):
    # connect to the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    # fetch the email details from the database using the email ID
    cur.execute('SELECT * FROM email WHERE id = ?', (email_id,))
    email = cur.fetchone()

    # close the database connection
    cur.close()
    conn.close()

    # check if the email exists in the database
    if email is None:
        abort(404)

    # render the email detail template with the email data
    return render_template('read_email.html', email=email)
        
@app.route('/inbox/<int:email_id>/delete')
def delete_email(email_id):
    # connect to the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    # fetch the email details from the database using the email ID
    cur.execute('DELETE FROM email WHERE id = ?', (email_id,))

    # commit the changes to the database
    conn.commit()

    # close the database connection
    cur.close()
    conn.close()

    # redirect the user to the inbox
    return redirect(url_for('inbox'))

@app.route('/email', methods=['POST'])
def email():
    if request.method == 'POST':
        # get the form data
        sender = session.get('email')
        recipient = request.form['recipient']
        subject = request.form['subject']
        body = request.form['body']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM keywords")
        keywords = c.fetchall()
        c.close()
        conn.close()

        nlp = spacy.load('en_core_web_sm')
        doc = nlp(body)
        matches = []
        for keyword in keywords:
            for token in doc:
                if token.text.lower() == keyword[1]:
                    matches.append(keyword[1])
                    
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()

        if matches:
            matches = set(matches)
            matches = ','.join(str(k) for k in matches)
            cur.execute('INSERT INTO email (sender, recipient, subject, body, threat, keywords) VALUES (?, ?, ?, ?, ?, ?)', (sender, recipient, subject, body, 1, matches))
        else:
            cur.execute('INSERT INTO email (sender, recipient, subject, body) VALUES (?, ?, ?, ?)', (sender, recipient, subject, body))

        conn.commit()

        cur.close()
        conn.close()
        return redirect(url_for('inbox'))
    
    else:
        return render_template('inbox.html')

@app.route('/dashboard/threat')
def threat():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("PRAGMA table_info(email);")
    headers = c.fetchall()
    headers = [t for t in headers if t[1] not in ['body', 'subject', 'threat', 'keywords']]
    
    c.execute("SELECT * FROM email WHERE threat = 1")
    threats = c.fetchall()
    c.close()
    threats = [(x[0], x[1], x[2], x[5], x[6], x[7]) for x in threats]

    
    conn.close()
    return render_template('dashboard.html', headers=headers, objects=threats, object_name = "threat")
    
@app.route('/dashboard/user')
def user():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("PRAGMA table_info(users);")
    headers = c.fetchall()
    
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    c.close()
    
    conn.close()
    return render_template('dashboard.html', headers=headers, objects=users, object_name = "users")

@app.route('/dashboard/keywords')
def keywords():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("PRAGMA table_info(keywords);")
    headers = c.fetchall()
    
    c.execute("SELECT * FROM keywords")
    keywords = c.fetchall()
    c.close()
    
    conn.close()
    return render_template('dashboard.html', headers=headers, objects=keywords, object_name = "keywords")

@app.route('/dashboard/addkeywords', methods=['GET'])
def addkeyword():
    return render_template('dashboard.html', object_name = "addkeywords")
    
@app.route('/dashboard/addkeywords', methods=['POST'])
def add_keyword():
    keyword = request.form['keyword']
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("PRAGMA table_info(keywords);")
    headers = c.fetchall()
    
    c.execute('INSERT INTO keywords (keyword) VALUES (?)', [keyword])
    conn.commit()  # commit changes using the connection object
    
    c.execute("SELECT * FROM keywords")
    keywords = c.fetchall()
    c.close()
    
    conn.close()
    return render_template('dashboard.html', headers=headers, objects=keywords, object_name="keywords")

@app.route('/dashboard/delkeywords/<int:keyword_id>')
def delete_keyword(keyword_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("PRAGMA table_info(keywords);")
    headers = c.fetchall()
    
    c.execute('DELETE FROM keywords WHERE id = ?', [keyword_id])
    conn.commit()
    
    c.execute("SELECT * FROM keywords")
    keywords = c.fetchall()
    c.close()
    
    conn.close()
    return render_template('dashboard.html', headers=headers, objects=keywords, object_name = "keywords")

if __name__ == '__main__':
    app.run()