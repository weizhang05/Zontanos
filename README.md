# NUS-CS3235-Project
A facial recognition project using the state of the art technology with liveness check.

<br/>

### Requirements

* Python 3
* Flask

<br/>

### Setting up

Install Flask, face_recognition, opencv-python, CMake, keras.

```
pip install Flask CMake face_recognition opencv-python keras
```

Install Flask SQLAlchemy.
```
pip install flask-sqlalchemy flask-login
```

Note: If you are on Windows and received a compilation error, install **Visual Studio for C++ development**.

<br/>

Set environmental variables

*Windows*

```
set FLASK_APP=Zontanos
```

*Linux*/Mac

```
export FLASK_APP=Zontanos
```

<br/>

### Starting server

Local only

```
flask run
```

Public accessible

```
flask run --host=0.0.0.0
```

Note: Ensure command is executed in the same directory as **Zontanos** folder.

<br/>

Open browser of choice (Chrome preferred) and go to **localhost:5000** .

<br/>

### References

<http://flask.palletsprojects.com/en/1.1.x/installation/#installation>

<http://flask.palletsprojects.com/en/1.1.x/quickstart/#quickstart>

