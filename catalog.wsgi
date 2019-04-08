import logging
import sys

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, "/var/www/catalog/")
sys.stdout = open('/home/grader/out.log', 'w');
from app import app as application

print("test");

application.secret_key = 'mykey'
