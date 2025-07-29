import pandas as pd
import os
import csv
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from config import AUTH_CSV
import re

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def sanitize_username(username):
    """Sanitize username to prevent CSV injection and invalid characters."""
    if not username or not re.match(r'^[a-zA-Z0-9_-]{3,30}$', username):
        return None
    if username.startswith(('-', '=', '+', '@')):
        return None
    return username.strip()

def get_auth_data(given_username):
    try:
        username = sanitize_username(given_username)
        if not username:
            logger.error(f"Invalid username format: {given_username}")
            return ""
        if not os.path.exists(AUTH_CSV):
            raise FileNotFoundError(f"'{AUTH_CSV}' not found")
        auth_df = pd.read_csv(AUTH_CSV, quotechar='"', encoding='utf-8')
        if auth_df.empty:
            raise ValueError(f"'{AUTH_CSV}' is empty")
        for _, row in auth_df.iterrows():
            if row[0] == username:
                return row[1].strip()  # Password hash
        return ""
    except Exception as e:
        logger.error(f"Error loading auth data: {e}")
        return ""

def username_exists(username):
    try:
        username = sanitize_username(username)
        if not username:
            return False
        if os.path.exists(AUTH_CSV):
            auth_df = pd.read_csv(AUTH_CSV, quotechar='"', encoding='utf-8')
            return username in auth_df.iloc[:, 0].values
        return False
    except Exception as e:
        logger.error(f"Error checking username existence: {e}")
        return False

def create_account(username, password):
    try:
        username = sanitize_username(username)
        if not username or not password:
            logger.error(f"Invalid username or password: {username}")
            return False
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        if os.path.exists(AUTH_CSV):
            df = pd.read_csv(AUTH_CSV)
            if 'profile_picture' not in df.columns:
                df['profile_picture'] = ''
                df.to_csv(AUTH_CSV, index=False)
        else:
            df = pd.DataFrame(columns=['username', 'password_hash', 'profile_picture'])
        new_row = pd.DataFrame([[username, password_hash, '']], columns=['username', 'password_hash', 'profile_picture'])
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv(AUTH_CSV, index=False, quoting=csv.QUOTE_ALL)
        logger.info(f"Created account for username: {username}")
        return True
    except Exception as e:
        logger.error(f"Error creating account: {e}")
        return False

def load_user_object(username):
    try:
        username = sanitize_username(username)
        if not username:
            return None
        if not os.path.exists(AUTH_CSV):
            return None
        auth_df = pd.read_csv(AUTH_CSV)
        for _, row in auth_df.iterrows():
            if row[0] == username:
                pic = None
                if 'profile_picture' in auth_df.columns and len(row) > 2:
                    pic = row[2] if str(row[2]).strip() != '' else None
                return {'username': username, 'profile_picture': pic}
        return None
    except Exception as e:
        logger.error(f"Error loading user object: {e}")
        return None

def update_user_profilepic(username, filename):
    try:
        username = sanitize_username(username)
        if not username:
            return False
        if not os.path.exists(AUTH_CSV):
            return False
        df = pd.read_csv(AUTH_CSV)
        if 'profile_picture' not in df.columns:
            df['profile_picture'] = ''
        for idx, row in df.iterrows():
            if row[0] == username:
                df.at[idx, 'profile_picture'] = filename
                df.to_csv(AUTH_CSV, index=False, quoting=csv.QUOTE_ALL)
                return True
        return False
    except Exception as e:
        logger.error(f"Error updating profile picture: {e}")
        return False
