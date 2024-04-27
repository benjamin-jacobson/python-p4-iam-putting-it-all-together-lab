#!/usr/bin/env python3

from flask_bcrypt import Bcrypt
# from flask.ext.bcrypt import Bcrypt
from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

bcrypt = Bcrypt(app)

@app.before_request
def check_if_logged_in():
    open_access_list = [
        'clear',
        'signup',
        'login',
        'logout',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

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

        if not User.query.filter(User.username == username).first():
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
        else: 
            return {'error': '422 Unprocessable Entity. Username Already exists'}, 422 # this is not working well
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
        password = request.get_json().get('password')
        user = User.query.filter(User.username == username).first()
        if user:
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        return {'error':'401 Unathorized: Username and/or password incorrect.'}, 401

        # The website needs to redirect or send a message in either scenario # TODO HERE!!!

class Logout(Resource):
    """
    Handle logout by implementing a DELETE /logout route. It should:

    Be handled in a Logout resource with a delete() method.
    In the delete() method, if the user is logged in (if their user_id is in the session object):
    Remove the user's ID from the session object.
    Return an empty response with an HTTP status code of 204 (No Content).
    If the user is not logged in when they make the request:
    Return a JSON response with an error message, and a status of 401 (Unauthorized).
    """
    def delete(self):

        if not session['user_id']:
            return {'error':'401 Unathorized. User not logged in.'}, 401
        
        # If there is a user_id
        session['user_id'] = None
        return {}, 204

class RecipeIndex(Resource):
    """
    Users should only be able to view recipes on our site after logging in.
    Handle recipe viewing by implementing a GET /recipes route. It should:
    Be handled in a RecipeIndex resource with a get() method
    In the get() method, if the user is logged in (if their user_id is in the session object):
    Return a JSON response with an array of all recipes with their title, instructions, and minutes to complete data along with a nested user object; and an HTTP status code of 200 (Success).
    If the user is not logged in when they make the request:
    Return a JSON response with an error message, and a status of 401 (Unauthorized).


    Handle recipe creation by implementing a POST /recipes route. It should:

    Be handled in the RecipeIndex resource with a post() method.
    In the post() method, if the user is logged in (if their user_id is in the session object):
    Save a new recipe to the database if it is valid. The recipe should belong to the logged in user, 
    and should have title, instructions, and minutes to complete data provided from the request JSON.
    Return a JSON response with the title, instructions, and minutes to complete data along with a
    nested user object; and an HTTP status code of 201 (Created).
    If the user is not logged in when they make the request:
    Return a JSON response with an error message, and a status of 401 (Unauthorized).
    If the recipe is not valid:
    Return a JSON response with the error messages, and an HTTP status code of 422 (Unprocessable Entity).
    After finishing the RecipeIndex resource, you're done! Make sure to check your work. 
    You should be able to run the full test suite now with pytest.

    """
    def get(self):
        response_dict_list  = [r.to_dict() for r in Recipe.query.all()]
        response = make_response(response_dict_list, 200 )
        return response

    def post(self):

        data = request.get_json()

        # minutesToComplete = request.form['minutesToComplete'] # if form instead of JSON
        # title = request.form['title']
        # instructions = request.form['instructions']
        try: 
            new_record = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete = data['minutes_to_complete'],
                user_id=session['user_id'])
            
            db.session.add(new_record)
            db.session.commit()

            response_dict = new_record.to_dict()

            response = make_response(response_dict, 201)
            return response
        except IntegrityError:

            return {'error': '422 Unprocessable Entity'}, 422

class ClearSession(Resource):

    def delete(self):
        session['user_id'] = None
        return {}, 204

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')
#api.add_resource(RecipeById, '/recipes', endpoint='recipes/<int:id>')
api.add_resource(ClearSession, '/clear', endpoint='clear')

if __name__ == '__main__':
    app.run(port=5555, debug=True)