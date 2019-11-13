from flask import Blueprint, render_template, redirect, session, url_for, request, flash, escape, Response, Flask
# from camera import VideoCamera 
import cv2
import face_recognition
import numpy as np
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db
from .otp import sentOtp
import re
import time
import flask
from flask import request, url_for, Response
from flask import flash, redirect, render_template, request, session, abort
import io
from PIL import Image
import requests
auth = Blueprint('auth', __name__)

# hypothetical link for clearing all sessions
@auth.route('/clear')
def clear():
    session.clear()
    return redirect(url_for('auth.login'))

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

        # successful login for correct otp entered
        if 'otp' in session:
            if otp == session['otp']:
                session.pop('otpTrial', None)
                session.pop('otp', None)
                session["otpCorrect"] = True
                return redirect(url_for('auth.facialrecognition'), code=307)
        
        session['otpTrial'] += 1

        # returns to home page after 2 wrong tries
        if session['otpTrial'] == 2:
            session.clear()
            return redirect(url_for('auth.login'))

        flash('Wrong OTP, please try again.')
        return render_template('otp.html')

    # error tracking
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
				print('Fake')
				user_status['face_recog'] = False
			else:
				user_status['face_recog'] = True
				session['faceRec'] = True
				print("True")
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
		print("Success")
		return redirect(url_for('main.profile'))

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

@auth.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('main.index'))

def gen(camera):
    while True:
        frame = camera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

@auth.route('/video_feed')
def video_feed():
    return Response(gen(VideoCamera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# Import does not work, so this is the best bet
class VideoCamera(object):
	def __init__(self):
		self.video = cv2.VideoCapture(0)
		
	def __del__(self):
		self.video.release()

	def get_frame(self):
		obama_image = face_recognition.load_image_file("Jin Xing.jpg")
		obama_face_encoding = face_recognition.face_encodings(obama_image)[0]
		known_face_encodings = [obama_face_encoding]
		known_face_names = ["Jin Xing","Sarah Cheok"]
		face_locations = []
		face_encodings = []
		face_names = []
		process_this_frame = True
		ret, frame = self.video.read()

		# Resize frame of video to 1/4 size for faster face recognition processing
		small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)

		# Convert the image from BGR color (which OpenCV uses) to RGB color (which face_recognition uses)
		rgb_small_frame = small_frame[:, :, ::-1]

		# Only process every other frame of video to save time
		if process_this_frame:
			# Find all the faces and face encodings in the current frame of video
			face_locations = face_recognition.face_locations(rgb_small_frame)
			face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations)

			face_names = []
			for face_encoding in face_encodings:
				# See if the face is a match for the known face(s)
				matches = face_recognition.compare_faces(known_face_encodings, face_encoding)
				name = "Unknown"

				# # If a match was found in known_face_encodings, just use the first one.
				# if True in matches:
				#     first_match_index = matches.index(True)
				#     name = known_face_names[first_match_index]

				# Or instead, use the known face with the smallest distance to the new face
				face_distances = face_recognition.face_distance(known_face_encodings, face_encoding)
				best_match_index = np.argmin(face_distances)
				if matches[best_match_index]:
					name = known_face_names[best_match_index]

				face_names.append(name)

		process_this_frame = not process_this_frame


		# Display the results
		for (top, right, bottom, left), name in zip(face_locations, face_names):
			# Scale back up face locations since the frame we detected in was scaled to 1/4 size
			top *= 4
			right *= 4
			bottom *= 4
			left *= 4

			# Draw a box around the face
			cv2.rectangle(frame, (left, top), (right, bottom), (0, 0, 255), 2)

			# Draw a label with a name below the face
			cv2.rectangle(frame, (left, bottom - 35), (right, bottom), (0, 0, 255), cv2.FILLED)
			font = cv2.FONT_HERSHEY_DUPLEX
			cv2.putText(frame, name, (left + 6, bottom - 6), font, 1.0, (255, 255, 255), 1)

		ret, jpeg = cv2.imencode('.jpg', frame)
		return jpeg.tobytes()
	
	def get_frame2(self):
		success, image = self.video.read()
        # We are using Motion JPEG, but OpenCV defaults to capture raw images,
        # so we must encode it into JPEG in order to correctly display the
        # video stream.
		ret, jpeg = cv2.imencode('.jpg', image)
		return jpeg.tobytes()
