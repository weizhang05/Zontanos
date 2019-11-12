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
import time
import flask
from flask import request, url_for, Response
from flask import flash, redirect, render_template, request, session, abort
import io
from PIL import Image

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

@auth.route('/login_user', methods=['POST'])
def login_user():
    session['email'] = request.form.get('email')
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
                return redirect(url_for('auth.do_login'), code=307)
        
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

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup_user', methods=['POST'])
def signup_user():
	known_face_encoding = [-0.0503066,0.10304856,0.00204806,-0.00389499,-0.03759966,
							-0.09018462,-0.04985043,-0.11552332,0.10075147,-0.05842667,
							0.2121045,-0.08577333,-0.213588,-0.14619818,-0.03819468,
							0.20927802,-0.19131684,-0.10849015,-0.0833607,-0.00487367,
							0.10962869,0.01902105,0.02119232,0.03458961,-0.0676399,
							-0.32420766,-0.06685217,-0.1253757,-0.06563466,-0.01856556,
							-0.02201398,0.04079891,-0.1656629,-0.08953712,0.0432549,
							0.0409674,-0.0715493,-0.07134749,0.20112692,-0.06966566,
							-0.20266852,-0.03234909,0.10976552,0.22679658,0.19811808,
							0.02655001,0.01308998,-0.11290134,0.11300361,-0.15953682,
							0.02025095,0.14173162,0.09588584,0.10748261,0.05977803,
							-0.07566036,0.06960371,0.09213795,-0.14075439,-0.03364062,
							0.0960448,-0.0871863,-0.04299871,-0.08072766,0.25391167,
							0.03685982,-0.11414248,-0.14813563,0.10489471,-0.14378215,
							-0.1229203,0.0293023,-0.13665946,-0.19299881,-0.32483345,
							-0.02783794,0.31240979,0.09899636,-0.20655565,0.06804011,
							-0.01659909,-0.02284967,0.17932656,0.14099914,0.03632857,
							0.03354897,-0.10749609,0.00128054,0.2078674,-0.11774533,
							-0.03962221,0.20906711,-0.02309964,0.02911466,0.02462435,
							-0.01325976,-0.02004067,0.07890908,-0.13797773,0.0380192,
							0.10960671,-0.00563727,-0.02076689,0.05862342,-0.06813609,
							0.06174087,0.01770549,0.08924914,0.01272873,-0.07172906,
							-0.1612789,-0.06534074,0.12753838,-0.16569392,0.22722113,0.09166601,
							0.00968798,0.07846366,0.11118621,0.09732923,-0.02296288,
							-0.06158877,-0.2623125,-0.0223248,0.14919193,0.03540958,0.10420216,0.00212763]

	if flask.request.method == "POST":
		email = request.form.get('email')
		name = request.form.get('name')
		password = request.form.get('password')
		user_status = {'registration': False, 'face_present': False, 'duplicate':False}
		
		user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

		if user: # if a user is found, we want to redirect back to signup page so user can try again
			flash('Email address already exists')
			user_status['duplicate'] = True
			#return redirect(url_for('auth.signup'))
		else:
			if flask.request.files.get("image"):
				# read the image in PIL format
				image = flask.request.files["image"].read()
				image = np.array(Image.open(io.BytesIO(image)))
				#print(face_recognition.face_encodings(image))
				print(face_recognition.compare_faces(face_recognition.face_encodings(image)[0], [known_face_encoding], tolerance=0.5))
				user_status['face_present'] = True
			else:
				user_status['face_present'] = False
			# create new user with the form data. Hash the password so plaintext version isn't saved.
			new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

			# add the new user to the database
			db.session.add(new_user)
			db.session.commit()
			user_status['registration'] = True
			flash('Successful Registration')
		
    #return redirect(url_for('auth.login'))
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
