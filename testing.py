from flask import Flask, render_template, request, redirect, url_for, session
import folium
import pandas as pd
import os
from math import radians, sin, cos, sqrt, atan2
import hashlib

def get_auth_data(given_username):
    file_path = os.path.join('Data', 'authenticate.csv')
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"'{file_path}' not found in {os.getcwd()}")
        authenticate_df = pd.read_csv(file_path, quotechar='"', encoding='utf-8')
        if authenticate_df.empty:
            raise ValueError(f"'{file_path}' is empty")
        
        print("CSV Columns:", authenticate_df.columns.tolist())
        password_hash = ""

        for _, row in authenticate_df.iterrows():
            username = row[0]  # Username
            
            if(username == given_username):
                password_hash = row[1]    # Password Hash
           
        return password_hash
        
    
    except Exception as e:
        print(f"Error loading airport data: {e}")
        return {}

print("flag")
hash = get_auth_data("laura.davis@us.af.mil")
print(hash)