import mysql.connector
from flask import g
from dotenv import load_dotenv
import os

load_dotenv()

def get_db_connection():
    if 'db_connection' not in g:
        g.db_connection = mysql.connector.connect(
            host=os.getenv('MYSQL_ADDON_HOST'),
            database=os.getenv('MYSQL_ADDON_DB'),
            user=os.getenv('MYSQL_ADDON_USER'),
            password=os.getenv('MYSQL_ADDON_PASSWORD'),
            port=os.getenv('MYSQL_ADDON_PORT')
        )
    return g.db_connection

def close_db_connection(e=None):
    db = g.pop('db_connection', None)
    if db is not None:
        db.close()
