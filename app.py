from flask import Flask, render_template, session, redirect, url_for, escape, request
from flask import Flask, render_template, Response
from camera import VideoCamera
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
def gen(camera):
    while True:
        frame = camera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

@app.route('/video_feed')
def video_feed():
    return Response(gen(VideoCamera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')
					
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

