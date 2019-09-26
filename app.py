from flask import Flask, render_template, session, redirect, url_for, escape, request
app = Flask(__name__)

import time

# Set the secret key to some random bytes. Keep this really secret!
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

SLEEP = 1

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # add user account
    if request.method == "POST":
        # TODO: register interaction with DB
        
        # assumes successful registration
        time.sleep(SLEEP)
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # process login
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        # TODO: login interaction with DB
        
        # assumes successful login
        time.sleep(SLEEP)
        return redirect(url_for('afterLogin'))
    
    return render_template('login.html')

# page for successful login
@app.route('/afterLogin')
def afterLogin():
    if "email" in session:
        return render_template('afterLogin.html')
    
    return redirect(url_for('index'))

# always redirects to home page
@app.errorhandler(404)
def page_not_found(error):
    #return render_template('page_not_found.html'), 404
    return redirect(url_for('index'))

