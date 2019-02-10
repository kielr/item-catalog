from flask import Flask, request, make_response, jsonify, render_template
from database_init import *
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

import json


# Declare app.
app = Flask(__name__, template_folder='./templates/')


# Connect to the Database.
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

sql_session = sessionmaker(bind=engine)
session = sql_session()


# Serves the login page.
@app.route('/login')
def show_login():
    return render_template('login.htm')


# Serve the front page.
@app.route('/', methods=['POST', 'GET'])
def show_home():
    if request.method == 'GET':
        return render_template('base.htm')


# Creates a new record in the item table.
@app.route('/items', methods=['POST'])
def new_item():
    if request.method == 'POST':
        print(request.get_json())
    return make_response(json.dumps("Good!"), 200)


if __name__ == '__main__':
    app.debug = True
    app.run(host='localhost', port=7080)