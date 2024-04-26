#!/usr/bin/env python3

from flask_bcrypt import Bcrypt
# from flask.ext.bcrypt import Bcrypt
from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

bcrypt = Bcrypt(app)

class Signup(Resource):
    """
    Handle sign up by implementing a `POST /signup` route. It should:

    - Be handled in a `Signup` resource with a `post()` method.
    - In the `post()` method, if the user is valid:
    - Save a new user to the database with their username, encrypted password,
        image URL, and bio.
    - Save the user's ID in the session object as `user_id`.
    - Return a JSON response with the user's ID, username, image URL, and bio; and
        an HTTP status code of 201 (Created).
    - If the user is not valid:
    - Return a JSON response with the error message, and an HTTP status code of
        422 (Unprocessable Entity).
    """
    def post(self):
        username = request.get_json().get('username')
        image_url = request.get_json().get('image_url') # add error catching

        bio = request.get_json().get('bio') # add error catching
        password = request.get_json().get('password') 

        # Attempting to create the user
        new_user = User(username = username,
                            image_url = image_url,
                            bio = bio)
        new_user.password_hash = password

        try:
            db.session.add(new_user)
            db.session.commit()

            user = User.query.filter(User.username == username).first() # so that have user id too
            session['user_id'] = user.id # saving use session
            return user.to_dict(), 201
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422

        # # Getting user informatino from the database after commit
        # user = User.query.filter(User.username == username).first()
        # if user:
        #     session['user_id'] = user.id # saving use session
        #     return user.to_dict(), 201

class CheckSession(Resource):
    """
    ### Auto-Login Feature

    Users can log into our app! 🎉 But we want them to **stay** logged in when they
    refresh the page, or navigate back to our site from somewhere else.

    Handle auto-login by implementing a `GET /check_session` route. It should:

    - Be handled in a `CheckSession` resource with a `get()` method.
    - In the `get()` method, if the user is logged in (if their `user_id` is in the
    session object):
    - Return a JSON response with the user's ID, username, image URL, and bio; and
        an HTTP status code of 200 (Success).
    - If the user is **not** logged in when they make the request:
    - Return a JSON response with an error message, and a status of 401
        (Unauthorized).

    Make sure the signup and auto-login features work as intended before moving
    forward. You can test the `CheckSession` requests with pytest:

    $ pytest testing/app_testing/app_test.py::TestCheckSession

    """

    def get(self):
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        else:
            return {'error':'401 User session not active, or user not in database.'}, 401

class Login(Resource):
    """
    - Be handled in a `Login` resource with a `post()` method.
    - In the `post()` method, if the user's username and password are authenticated:
    - Save the user's ID in the session object.
    - Return a JSON response with the user's ID, username, image URL, and bio.
    - If the user's username and password are not authenticated:
    - Return a JSON response with an error message, and a status of 401 (Unauthorized).
    """
    def post(self):
        username = request.get_json().get('username')
        user = User.query.filter(User.username == username).first()
        if user:
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error':'401: Username and/or password incorrect.'}, 401

class Logout(Resource):
    pass

class RecipeIndex(Resource):
    pass

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)