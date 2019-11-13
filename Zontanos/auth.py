# flask based dependencies
from flask import Blueprint, render_template, redirect, session, url_for, request, flash, escape, Response, Flask, abort
from flask_login import login_user, logout_user, login_required
# functions from local files
from .models import User
from . import db
from .otp import sentOtp
# other dependencies
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import cv2, face_recognition
import numpy as np
import re, time, io, requests

auth = Blueprint('auth', __name__)

# hypothetical link for clearing all sessions
@auth.route('/clear')
def clear():
    session.clear()
    return redirect(url_for('auth.login'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup_user', methods=['POST'])
def signup_post():
    if flask.request.method == "POST":
        email = request.form.get('email')
        name = request.form.get('name')
        password = str(request.form['pass'])
        image = request.form.get('image')
        user_status = {'registration': False, 'face_present': False, 'duplicate':False}
        user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database
        if user: # if a user is found, we want to redirect back to signup page so user can try again
            flash('Email address already exists')
            user_status['duplicate'] = True
        else:
            if flask.request.files.get("image"):
                # read the image in PIL format
                image = flask.request.files["image"].read()
                image = np.array(Image.open(io.BytesIO(image)))
                #print(face_recognition.face_encodings(image))
                #print(face_recognition.compare_faces(face_recognition.face_encodings(image)[0], [known_face_encoding], tolerance=0.5))
                facerecoVal = face_recognition.face_encodings(image)
                user_status['face_present'] = True
            else:
                user_status['face_present'] = False
                
            # create new user with the form data. Hash the password so plaintext version isn't saved.
            new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'), facereco=str(re.sub("\s+", ",", str(facerecoVal[0]))))
            # add the new user to the database
            db.session.add(new_user)
            db.session.commit()
            user_status['registration'] = True

    return flask.jsonify(user_status)

@auth.route('/login')
def login():
    session.clear()
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    session['email'] = request.form.get('email')
    session['faceRec'] = False
    password = request.form.get('password')
    session['rmb'] = True if request.form.get('remember') else False

    user = User.query.filter_by(email=session['email']).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password): 
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    # proceed to otp authentication once credentials are cleared
    return redirect(url_for('auth.otp'), code=307)

@auth.route('/otp', methods=['POST'])
def otp():
    if 'otpTrial' in session:
        otp = request.form.get('otp')

        if 'otp' in session:
            # successful login for correct otp entered
            if otp == session['otp']:
                session.pop('otpTrial', None)
                session.pop('otp', None)
                session["otpCorrect"] = True
                return redirect(url_for('auth.facialrecognition'), code=307)
        
            session['otpTrial'] += 1

            # returns to login page after 2 wrong tries
            if session['otpTrial'] == 2:
                session.clear()
                return redirect(url_for('auth.login'))

            flash('Wrong OTP, please try again.')
            return render_template('otp.html')

    # for tracking number of wrong OTP entries from user
    session['otpTrial'] = 0
    session['otp'] = sentOtp()
    return render_template('otp.html')

@auth.route('/facialrecognition', methods=['POST'])
def facialrecognition():
    return render_template('facialrecognition.html')
	
@auth.route('/do_facialrecognition', methods=['POST'])
def do_facialrecognition():
    user_status = {'face_recog': False}
    if flask.request.method == "POST":
        user = User.query.filter_by(email=session['email']).first()
        if flask.request.files.get("image"):
            image = flask.request.files["image"].read()
            image = np.array(Image.open(io.BytesIO(image)))
            facerecoVal = face_recognition.face_encodings(image)[0]
            npA = np.asarray(list(map(float, str(re.sub("\s+", ",", str(user.facereco)))[1:-1].split(","))), dtype=np.float32)
            if not face_recognition.compare_faces([facerecoVal], npA, tolerance=0.9):
                flash('Face not recognized')
                user_status['face_recog'] = False
            else:
                user_status['face_recog'] = True
                session['faceRec'] = True
                return redirect(url_for('auth.do_login'), code=307)
                            
    return flask.jsonify(user_status)	

# officially logins the user once credentials and OTP is satisfied
@auth.route('/do_login', methods=['POST'])
def do_login():
    # this is to ensure the user does not forge a fake login
    if 'otpCorrect' in session:
        user = User.query.filter_by(email=session['email']).first()
        login_user(user, remember=session['rmb'])
        session.pop('otpCorrect', None)
        session.pop('email', None)
        session.pop('rmb', None)
        return redirect(url_for('main.profile'))
    
    session.clear()
    return redirect(url_for('auth.login'))



@auth.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('main.index'))
