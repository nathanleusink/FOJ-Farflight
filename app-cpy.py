import os
import secrets
import io
import csv
import hashlib
from datetime import datetime
from flask import (Flask, render_template, request, redirect,
                   url_for, session, Response, send_file,
                   send_from_directory)
from werkzeug.utils import secure_filename
from subprocess import Popen

from config import *
from utils import create_map, optimize_route, proxy_tiles
from data import load_tail_numbers, load_user_routes, save_route, process_uploaded_routes, delete_route, get_coordinates
from auth import get_auth_data, username_exists, create_account, load_user_object, update_user_profilepic

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Upload folder path - make sure this directory exists and is writable
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# No extension restriction (allow all files)
# IMPORTANT: Be very cautious, this enables arbitrary file upload!

def allowed_file(filename):
    # Disable extension check, accept all files
    return True

@app.context_processor
def inject_user():
    username = session.get('username')
    if username:
        user_obj = load_user_object(username)
    else:
        user_obj = None
    return dict(user=user_obj)


@app.route('/proxy/tiles/<int:z>/<int:x>/<int:y>.png')
def proxy_tiles_route(z, x, y):
    content, mimetype, status = proxy_tiles(z, x, y)
    return Response(content, mimetype=mimetype, status=status)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Serves uploaded files directly (including scripts)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
        verified_hash = get_auth_data(username)
        if password_hash == verified_hash and verified_hash:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html', error=None)


@app.route('/request_account', methods=['GET', 'POST'])
def request_account():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            return render_template('request_account.html', error="Username and password are required")
        if username_exists(username):
            return render_template('request_account.html', error="Username already exists")
        if create_account(username, password):
            return render_template('login.html', success="Account created successfully. Please log in.")
        else:
            return render_template('request_account.html', error="Failed to create account. Please try again.")
    return render_template('request_account.html', error=None)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))


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


@app.route('/account')
def account():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    username = session.get('username')
    user = load_user_object(username)
    return render_template('account.html', user=user)


@app.route('/edit_account', methods=['GET', 'POST'])
def edit_account():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))

    username = session.get('username')
    user = load_user_object(username)
    error = None
    success = None

    if request.method == 'POST':
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(save_path)
                # If the file is a shell script or any executable, you can run it *if desired*
                # Example (commented out, *uncomment to run scripts* - dangerous!):
                # if filename.endswith('.sh'):
                #     Popen(['/bin/bash', save_path])
                update_user_profilepic(username, filename)
                user = load_user_object(username)  # refresh user info
                success = "Profile picture updated."
            else:
                error = "No file selected."
        else:
            error = "No file part in request."

    return render_template('edit_account.html', user=user, error=error, success=success)

