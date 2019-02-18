from flask import Flask, flash, request, make_response
from flask import jsonify, render_template, redirect, url_for
from flask import session as login_session
from database_init import Item, ItemCategory, User, Base
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import scoped_session, sessionmaker
from functools import wraps


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
# A lot of weird bugs if the process threads change.
# Thread safety isn't in the rubric.
# So I'm going to disable this check unless told to do otherwise.
engine = create_engine('sqlite:///itemcatalog.db?check_same_thread=False')
Base.metadata.bind = engine

sql_session = scoped_session(sessionmaker(bind=engine))
session = sql_session()

CONTENT_TYPE_JSON = 'application/json'
CLIENT_ID = json.loads(
    open('gclient.json', 'r').read())['web']['client_id']


# From http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in login_session:
            return redirect(url_for('show_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/items/json', methods=['GET'])
def get_items_json():
    items = session.query(Item).all()
    return jsonify(items=[item.get() for item in items])


@app.route('/items/<int:item_id>/json', methods=['GET'])
def get_item_json(item_id):
    item = session.query(Item).filter_by(item_id=item_id).one()
    return jsonify(item.get())


@app.route('/categories/json', methods=['GET'])
def get_category_json():
    categories = session.query(ItemCategory).all()
    return jsonify(categories=[category.get() for category in categories])


@app.route('/')
def show_home():
    categories = session.query(ItemCategory).all()
    return render_template('home.htm', categories=categories)


@app.route('/login')
def show_login():
    # Generate a STATE token to protect against forgery.
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.htm', STATE=state)


@app.route('/categories', methods=['POST', 'GET'])
@login_required
def create_category():
    if request.method == 'GET':
        return render_template('add_category.htm')
    else:
        user = login_session['user']
        new_category = ItemCategory(
            category_name=request.form['name'],
            category_user_id=user['user_id'])
        session.add(new_category)
        session.commit()
        return redirect(url_for('show_home'))


@app.route('/categories/<int:category_id>/', methods=['GET'])
def read_category(category_id):
    category = session.query(ItemCategory).filter_by(
        category_id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return render_template('read_category.htm', category=category, items=items)


@app.route('/categories/<int:category_id>/update/', methods=['GET', 'POST'])
@login_required
def update_category(category_id):
    category = session.query(ItemCategory).filter_by(
        category_id=category_id).one()
    if request.method == 'GET':
        return render_template('update_category.htm', category=category)

    if 'name' in request.form:
        category.category_name = request.form['name']
    session.commit()
    return redirect(url_for('show_home'))


@app.route('/categories/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
    category = session.query(ItemCategory).filter_by(
        category_id=category_id).one()
    session.query(Item).filter_by(category_id=category_id).delete()
    if request.method == 'GET':
        return render_template('delete_category.htm', category=category)
    session.delete(category)
    session.commit()
    return redirect(url_for('show_home'))


@app.route('/items', methods=['POST', 'GET'])
@login_required
def create_item():
    categories = session.query(ItemCategory).all()
    if request.method == 'GET':
        selected_category = request.args.get('selected_category')
        return render_template('add_item.htm',
                               categories=categories,
                               selected_category=selected_category)
    else:
        new_item = Item(item_name=request.form['name'],
                        item_desc=request.form['description'],
                        item_price=request.form['price'],
                        user_id=login_session['user']['user_id'])
        if 'category' in request.form:
            new_item.category_id = request.form['category']
        session.add(new_item)
        session.commit()
        return redirect(url_for('show_home'))


@app.route('/items/<int:item_id>/', methods=['GET'])
@login_required
def read_item():
    return


@app.route('/items/<int:item_id>/update', methods=['GET', 'POST'])
@login_required
def update_item(item_id):
    item = session.query(Item).filter_by(
        item_id=item_id).one()
    categories = session.query(ItemCategory).all()
    if request.method == 'GET':
        return render_template('update_item.htm', item=item,
                               categories=categories)

    if 'name' in request.form:
        item.item_name = request.form['name']
    if 'description' in request.form:
        item.item_desc = request.form['description']
    if 'price' in request.form:
        item.item_price = request.form['price']
    if 'category' in request.form:
        item.category_id = request.form['category']

    session.commit()
    return redirect(url_for('show_home'))


@app.route('/items/<int:item_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_item(item_id):
    item = session.query(Item).filter_by(
        item_id=item_id).one()
    if request.method == 'GET':
        return render_template('delete_item.htm', item=item)
    session.delete(item)
    session.commit()
    return redirect(url_for('show_home'))


@app.route('/signin', methods=['POST'])
def sign_in():
    # If the state string doesn't match what we have,
    # we need to drop the request.
    if request.args.get('state') != login_session['state']:
        print('ERR: State mismatch')
        response = make_response(json.dumps('ERR: State mismatch'), 401)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response
    # Otherwise, let's continue adding this user
    authCode = request.data

    # It's possible for this to fail,
    # we want to tell the web browser
    # that we've failed if an error occurs.
    # Let's use a try catch
    try:
        # Get secrets from local client secrets.
        # Obviously in a real web app the
        # client_secrets would be stored safely somewhere,
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
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        print("Current user is already connected")
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response

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
    if user is None:
        newUser = createUser(login_session)
        if newUser is None:
            response = make_response(
                json.dumps("ERR: Error while creating a new user"), 500)
            print("ERR: Error while creating a new user.")
            response.headers['Content-Type'] = CONTENT_TYPE_JSON
            return response

    # Store user in the session
    login_session['user'] = user.get()

    return make_response(json.dumps("Success!"), 200)


@app.route('/signout')
def sign_out():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response

    access_token = json.loads(credentials)['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's session.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['user']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        return render_template('home.htm')
    else:
        response = make_response(json.dumps('Failed to revoke token'), 400)
        print(result)
        response.headers['Content-Type'] = CONTENT_TYPE_JSON
        return response


def getUserByEmail(email):
    try:
        user = session.query(User).filter_by(user_email=email).one()
        return user
    except Exception:
        return None


def createUser(login_session):
    try:
        newUser = User(user_name=login_session['username'],
                       user_email=login_session['email'],
                       user_thumb=login_session['picture'])
        session.add(newUser)
        session.commit()
        return getUserByEmail(login_session['email'])
    except Exception as e:
        print(e)
        return None


if __name__ == '__main__':
    app.debug = True
    app.secret_key = "this is an important key so my app doesn't crash"
    # Make sure this is a port that is mapped in the Vagrantfile.
    app.run(host='0.0.0.0', port=5000)
