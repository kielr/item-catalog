from flask import Flask, request, make_response, jsonify
from database_init import *
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

import json


# Declare app.
app = Flask(__name__)


# Connect to the Database.
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

sql_session = sessionmaker(bind=engine)
session = sql_session()

# Creates a new record in the item table.
@app.route('/items', methods=['POST'])
def new_item():
    if request.method == 'POST':
        print(request.get_json())
    
    return make_response(json.dumps("Good!"), 200)


if __name__ == '__main__':
    app.debug = True
    app.run(host='localhost', port=7080)