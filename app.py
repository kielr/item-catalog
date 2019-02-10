from flask import Flask, request, make_response, jsonify, render_template
from flask import session as login_session
from database_init import *
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker


from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import json
import random
import string
import httplib2
import requests

# Declare app.
app = Flask(__name__, template_folder='./templates/')


# Connect to the Database.
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

sql_session = sessionmaker(bind=engine)
session = sql_session()

CONTENT_TYPE_JSON = 'application/json'
CLIENT_ID = json.loads(
    open('gclient.json', 'r').read())['web']['client_id']

# Serve the front page.
@app.route('/', methods=['POST', 'GET'])
def show_home():
    if request.method == 'GET':
        return render_template('base.htm')

# Serves the login page.
@app.route('/login')
def show_login():
    # Generate a STATE token to protect against forgery. From Udacity lesson
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.htm', STATE=state)

# Handle sign in requests from the browser
@app.route('/signin', methods=['POST'])
def sign_in():
    # If the state string doesn't match what we have, we need to drop the request.
    if request.args.get('state') != login_session['state']:
        print('ERR: State mismatch')
        response = make_response(json.dumps('ERR: State mismatch'), 401)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response
    # Otherwise, let's continue adding this user
    authCode = request.data

    # It's possible for this to fail, we want to tell the web browser that we've failed if an error occurs.
    # Let's use a try catch
    try:
        # Get secrets from local client secrets. Obviously in a real web app the client_secrets would be stored safely somewhere,
        # but for now we can just load them directly here.
        oauth = flow_from_clientsecrets('gclient.json', scope='')
        oauth.redirect_uri = 'postmessage'
        credentials = oauth.step2_exchange(authCode)
    except FlowExchangeError as e:
        print(e)
        response = make_response(json.dumps("ERR: Oauth failure"), 401)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("ERR: Token's client ID does not match app's."), 401)
        print("ERR: Token's client ID does not match app's.")
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response

    # Check to see if user is already logged in
    # stored_credentials = login_session.get('credentials')
    # stored_gplus_id = login_session.get('gplus_id')
    # if stored_credentials is not None and gplus_id == stored_gplus_id:
    #     print("Current user is already connected")
    #     response = make_response(json.dumps(
    #         'Current user is already connected.'), 200)
    #     response.headers['Content-Type'] = CONTENT_TYPE_JSON
    #     return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Next, we need to check to see if the user exists in our User table
    user = getUserByEmail(login_session['email'])
    if user == None:
        newUser = createUser(login_session)
        if newUser == None:
            response = make_response(
                json.dumps("ERR: Error while creating a new user"), 500)
            print("ERR: Error while creating a new user.")
            response.headers['Content-Type'] = CONTENT_TYPE_JSON
            return response

    return make_response(json.dumps("Success!"), 200)


def getUserByEmail(email):
    try:
        user = session.query(User).filter_by(user_email=email).one()
        return user
    except:
        return None


def createUser(login_session):
    try:
        newUser = User(user_name=login_session['username'],
                       user_email=login_session['email'], user_thumb=login_session['picture'])
        session.add(newUser)
        session.commit()
        return getUserByEmail(login_session['email'])
    except Exception as e:
        print(e)
        return None

# Creates a new record in the item table.
@app.route('/items', methods=['POST'])
def new_item():
    if request.method == 'POST':
        print(request.get_json())
    return make_response(json.dumps("Good!"), 200)


if __name__ == '__main__':
    app.debug = True
    app.secret_key = "this is an important key so my app doesn't crash"
    # Make sure this is a port that is mapped in the Vagrantfile.
    app.run(host='0.0.0.0', port=5000)
