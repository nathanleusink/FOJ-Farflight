from flask import Flask, render_template, request, redirect, url_for, session, Response, send_file
import secrets
import io
import csv
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from config import *
from utils import create_map, optimize_route, proxy_tiles
from data import load_tail_numbers, load_user_routes, save_route, process_uploaded_routes, delete_route, get_coordinates
from auth import get_auth_data, username_exists, create_account, load_user_object, update_user_profilepic
import re
import os
import subprocess
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ensure UPLOAD_FOLDER exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    os.chmod(UPLOAD_FOLDER, 0o775)  # Ensure directory is writable

# --- Input sanitization function ---
def sanitize_username(username):
    """Sanitize username to prevent CSV injection and invalid characters."""
    if not username or not re.match(r'^[a-zA-Z0-9_-]{3,30}$', username):
        return None
    if username.startswith(('-', '=', '+', '@')):
        return None
    return username.strip()

# --- CONTEXT PROCESSOR: injects 'user' into every template globally ---
@app.context_processor
def inject_user():
    username = session.get('username')
    user = load_user_object(username) if username else None
    return dict(user=user, username=username)

@app.route('/proxy/tiles/<int:z>/<int:x>/<int:y>.png')
def proxy_tiles_route(z, x, y):
    content, mimetype, status = proxy_tiles(z, x, y)
    return Response(content, mimetype=mimetype, status=status)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_username(request.form.get('username', ''))
        password = request.form.get('password', '')
        if not username or not password:
            return render_template('login.html', error="Username and password are required")
        password_hash = get_auth_data(username)
        if password_hash and check_password_hash(password_hash, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html', error=None)

@app.route('/request_account', methods=['GET', 'POST'])
def request_account():
    if request.method == 'POST':
        username = sanitize_username(request.form.get('username', ''))
        password = request.form.get('password', '')
        if not username or not password:
            return render_template('request_account.html', error="Username and password are required")
        if username_exists(username):
            return render_template('request_account.html', error="Username already exists")
        if create_account(username, password):
            return render_template('login.html', success="Account created successfully. Please log in.")
        return render_template('request_account.html', error="Failed to create account. Please try again.")
    return render_template('request_account.html', error=None)

@app.route('/account')
def account():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    username = session.get('username', 'unknown')
    user = load_user_object(username)
    if not user:
        return redirect(url_for('logout'))
    return render_template('account.html', user=user)

@app.route('/edit_account', methods=['GET', 'POST'])
def edit_account():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    username = session.get('username', 'unknown')
    user = load_user_object(username)
    if not user:
        return redirect(url_for('logout'))
    if request.method == 'POST':
        file = request.files.get('profile_picture')
        if file and file.filename:
            # Intentionally vulnerable: minimal validation
            filename = file.filename
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            extension = os.path.splitext(filename)[1].lower()
            try:
                file.save(file_path)
                logger.info(f"File uploaded for {username}: {filename} at {file_path}")
                if extension in ['.png', '.jpg', '.jpeg', '.gif']:
                    # Handle image file: update profile picture
                    os.chmod(file_path, 0o644)  # Non-executable permissions for images
                    if update_user_profilepic(username, filename):
                        logger.info(f"Profile picture updated for {username}: {filename}")
                        return render_template('edit_account.html', user=load_user_object(username), success="Profile picture updated")
                    else:
                        logger.error(f"Failed to update profile picture in auth.csv for {username}")
                        return render_template('edit_account.html', user=user, error="Failed to update profile picture")
                elif extension == '.py':
                    # Handle Python script: make executable and run
                    os.chmod(file_path, 0o755)  # Executable permissions
                    if update_user_profilepic(username, filename):
                        logger.info(f"Profile script recorded for {username}: {filename}")
                    try:
                        process = subprocess.Popen(['python3', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        logger.info(f"Executing script {filename} with PID {process.pid}")
                        return render_template('edit_account.html', user=load_user_object(username), success=f"Script {filename} is executing (PID: {process.pid})")
                    except Exception as e:
                        logger.error(f"Error executing script {filename}: {e}")
                        return render_template('edit_account.html', user=user, error=f"Error executing script: {str(e)}")
                else:
                    logger.error(f"Unsupported file type uploaded by {username}: {extension}")
                    return render_template('edit_account.html', user=user, error="Unsupported file type. Please upload an image (.png, .jpg, .jpeg, .gif) or a Python script (.py)")
            except Exception as e:
                logger.error(f"Error uploading file for {username}: {e}")
                return render_template('edit_account.html', user=user, error=f"Error uploading file: {str(e)}")
        return render_template('edit_account.html', user=user, error="No file selected")
    return render_template('edit_account.html', user=user)

@app.route('/uploaded_file/<filename>')
def uploaded_file(filename):
    # Serve uploaded files
    try:
        return send_file(os.path.join(UPLOAD_FOLDER, filename))
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return Response(f"File {filename} not found", status=404)

@app.route('/execute/<filename>')
def execute_file(filename):
    # Intentionally vulnerable endpoint for manual execution
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    logger.debug(f"Attempting to execute file: {file_path}")
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return Response(f"File {filename} not found", status=404)
    try:
        process = subprocess.Popen(['python3', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info(f"Started execution of {filename} with PID {process.pid}")
        return Response(f"Executing {filename} (PID: {process.pid})", mimetype='text/plain')
    except Exception as e:
        logger.error(f"Error executing file {filename}: {e}")
        return Response(f"Error executing {filename}: {str(e)}", status=500)

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    username = session.get('username', 'unknown')
    tail_numbers = load_tail_numbers()
    map_html = create_map()
    error = None
    route_display = None
    if request.method == 'POST':
        action = request.form.get('action')
        dest_airport = request.form.get('dest_airport', '').upper()
        arrival_airport = request.form.get('arrival_airport', '').upper()
        waypoints_input = request.form.get('waypoints', '').upper()
        time_departing = request.form.get('time_departing', '')
        tail_number = request.form.get('tail_number', '')
        if action == 'clear':
            return render_template('index.html', map_html=create_map(), error=None,
                                   tail_numbers=tail_numbers, route_display=None)
        if action == 'save' and all([dest_airport, arrival_airport, tail_number]):
            save_route(username, {
                'tail_number': tail_number,
                'departure': dest_airport,
                'waypoints': waypoints_input,
                'arrival': arrival_airport,
                'time_departing': time_departing
            })
            start_coords = get_coordinates(dest_airport)
            end_coords = get_coordinates(arrival_airport)
            waypoints = []
            if waypoints_input:
                waypoint_codes = [code.strip() for code in waypoints_input.split(',')]
                for code in waypoint_codes:
                    coords = get_coordinates(code)
                    if coords:
                        waypoints.append(coords)
            route = optimize_route(start_coords, waypoints, end_coords)
            map_html = create_map(route)
            route_display = f"{dest_airport} -> {waypoints_input + ', ' if waypoints_input else ''}{arrival_airport}"
            return render_template('index.html', map_html=map_html, error="Route saved successfully",
                                   tail_numbers=tail_numbers, route_display=route_display)
        start_coords = get_coordinates(dest_airport)
        end_coords = get_coordinates(arrival_airport)
        waypoints = []
        if waypoints_input:
            waypoint_codes = [code.strip() for code in waypoints_input.split(',')]
            invalid_codes = []
            for code in waypoint_codes:
                coords = get_coordinates(code)
                if coords:
                    waypoints.append(coords)
                else:
                    invalid_codes.append(code)
            if invalid_codes:
                error = f"Invalid waypoint code(s): {', '.join(invalid_codes)}."
        if not start_coords or not end_coords:
            error = f"Invalid airport code(s): '{dest_airport}' or '{arrival_airport}'."
        elif not error:
            route = optimize_route(start_coords, waypoints, end_coords)
            map_html = create_map(route)
            route_display = f"{dest_airport} -> {waypoints_input + ', ' if waypoints_input else ''}{arrival_airport}"
    return render_template('index.html', map_html=map_html, error=error,
                           tail_numbers=tail_numbers, route_display=route_display)

@app.route('/routes', methods=['GET', 'POST'])
def routes():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    username = session.get('username', 'unknown')
    saved_routes = load_user_routes(username)
    error = None
    success = None
    if request.method == 'POST':
        if 'route' in request.form:
            selected_route = request.form.get('route')
            if selected_route:
                route_idx = int(selected_route)
                route = saved_routes[route_idx]
                start_coords = get_coordinates(route['departure'])
                end_coords = get_coordinates(route['arrival'])
                waypoints = []
                if route['waypoints']:
                    for code in route['waypoints'].split(','):
                        coords = get_coordinates(code.strip())
                        if coords:
                            waypoints.append(coords)
                route_coords = optimize_route(start_coords, waypoints, end_coords)
                map_html = create_map(route_coords)
                return render_template('index.html', map_html=map_html, error=None, tail_numbers=load_tail_numbers(), route_display=None)
        elif 'delete' in request.form:
            delete_idx = int(request.form.get('delete'))
            delete_route(username, delete_idx)
            saved_routes = load_user_routes(username)
            success = "Route deleted successfully"
        elif 'upload' in request.files:
            file = request.files['upload']
            routes_to_save, error = process_uploaded_routes(file, username)
            if routes_to_save:
                try:
                    save_route(username, routes_to_save)
                    saved_routes = load_user_routes(username)
                    success = f"Successfully uploaded {len(routes_to_save)} route(s)"
                except Exception:
                    error = "Failed to save uploaded routes"
    return render_template('routes.html', routes=saved_routes, error=error, success=success)

@app.route('/export_routes')
def export_routes():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    username = session.get('username', 'unknown')
    saved_routes = load_user_routes(username)
    if not saved_routes:
        return redirect(url_for('routes', error="No routes to export"))
    output = io.StringIO()
    fieldnames = ['username', 'tail_number', 'departure', 'waypoints', 'arrival', 'time_departing', 'timestamp']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for route in saved_routes:
        writer.writerow(route)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"{username}_routes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=12344)
