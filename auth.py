import pandas as pd
import os
import csv
import hashlib
import logging
from config import AUTH_CSV

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_auth_data(given_username):
    try:
        if not os.path.exists(AUTH_CSV):
            raise FileNotFoundError(f"'{AUTH_CSV}' not found")
        auth_df = pd.read_csv(AUTH_CSV, quotechar='"', encoding='utf-8')
        if auth_df.empty:
            raise ValueError(f"'{AUTH_CSV}' is empty")
        
        for _, row in auth_df.iterrows():
            if row[0] == given_username:
                return row[1].strip()  # Password hash
        return ""
    except Exception as e:
        logger.error(f"Error loading auth data: {e}")
        return ""

def username_exists(username):
    try:
        if os.path.exists(AUTH_CSV):
            with open(AUTH_CSV, 'r') as file:
                csv_reader = csv.reader(file)
                for row in csv_reader:
                    if row and row[0] == username:
                        return True
        return False
    except Exception as e:
        logger.error(f"Error checking username existence: {e}")
        return False

def create_account(username, password):
    try:
        password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
        with open(AUTH_CSV, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([username, password_hash])
        logger.info(f"Created account for username: {username}")
        return True
    except Exception as e:
        logger.error(f"Error creating account: {e}")
        return False