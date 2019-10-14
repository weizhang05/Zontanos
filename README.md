# NUS-CS3235-Project
A facial recognition project using the state of the art technology with liveness check.

<br/>

### Requirements

* Python 3
* Flask

<br/>

### Setting up

Install Flask, face_recognition, opencv-python, CMake, keras

```
pip install Flask face_recognition opencv-python CMake keras
```

Install Flask SQLAlchemy
```
pip install flask-sqlalchemy flask-login
```

<br/>

Set environmental variables

Rename project as `Zontanos`

*Windows*

```
set FLASK_APP=Zontanos
```

*Linux*

```
export FLASK_APP=Zontanos
export FLASK_DEBUG=1
```

<br/>

### Starting server

```
flask run
```

Note: Ensure command is executed in the outside of the directory as **__init__.py**

<br/>

Open browser of choice (Chrome preferred) and go to **localhost:5000**

<br/>

### References

<http://flask.palletsprojects.com/en/1.1.x/installation/#installation>

<http://flask.palletsprojects.com/en/1.1.x/quickstart/#quickstart>

