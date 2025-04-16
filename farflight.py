##
# Author: 1st Lt Nathan Leusink
# SOURCE: https://ourairports.com/data/
##

from flask import Flask, render_template, request, redirect, url_for, session, Response, send_file
import folium
import sqlite3
from math import radians, sin, cos, sqrt, atan2
import hashlib
import requests
import logging
import secrets
from dotenv import load_dotenv
import csv
from datetime import datetime
import io
import os
from werkzeug.utils import secure_filename
import subprocess

load_dotenv()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DATABASE = 'farflight.db'
UPLOAD_FOLDER = 'Uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'csv'}

OPENAIP_TILES = 'https://a.api.tiles.openaip.net/api/data/openaip/{z}/{x}/{y}.png'
OPENAIP_API_KEY = os.getenv('OPENAIP_API_KEY') or '447847231b754a78e6e70354f2a3365a'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS airports (
                iata_code TEXT PRIMARY KEY,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                profile_picture TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tailnumbers (
                tail_number TEXT PRIMARY KEY
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flight_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                tail_number TEXT NOT NULL,
                departure TEXT NOT NULL,
                waypoints TEXT,
                arrival TEXT NOT NULL,
                time_departing TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username),
                FOREIGN KEY (tail_number) REFERENCES tailnumbers(tail_number),
                FOREIGN KEY (departure) REFERENCES airports(iata_code),
                FOREIGN KEY (arrival) REFERENCES airports(iata_code)
            )
        ''')
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT")
        except sqlite3.OperationalError:
            pass
        conn.commit()
    logger.info("Database initialized.")

init_db()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

def load_airport_data():
    logger.info("Loading airport data...")
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT iata_code, latitude, longitude FROM airports")
            rows = cursor.fetchall()
            coordinates = {row['iata_code']: {'latitude': row['latitude'], 'longitude': row['longitude']} for row in rows}
        logger.info(f"Loaded {len(coordinates)} airports")
        return coordinates
    except Exception as e:
        logger.error(f"Error loading airport data: {e}")
        return {}

airport_coordinates = load_airport_data()
if not airport_coordinates:
    logger.error("No airport data loaded. Exiting.")
    exit(1)

def get_coordinates(airport_code):
    result = airport_coordinates.get(airport_code.upper())
    if not result:
        logger.warning(f"No coordinates found for airport code: {airport_code}")
    return result

def optimize_route(start_coords, waypoints, end_coords):
    if not start_coords or not end_coords:
        logger.error("Missing start or end coordinates for route optimization")
        return []
    if not waypoints:
        return [start_coords, end_coords]
    route = [start_coords]
    remaining = waypoints[:]
    current = start_coords
    while remaining or route[-1] != end_coords:
        next_points = remaining + ([end_coords] if route[-1] != end_coords else [])
        if not next_points:
            break
        nearest = min(next_points, key=lambda p: haversine(
            current['latitude'], current['longitude'], p['latitude'], p['longitude']))
        route.append(nearest)
        current = nearest
        if nearest in remaining:
            remaining.remove(nearest)
    total_dist = sum(haversine(route[i]['latitude'], route[i]['longitude'],
                               route[i+1]['latitude'], route[i+1]['longitude'])
                     for i in range(len(route)-1))
    logger.info(f"Optimized route distance: {total_dist:.2f} km")
    return route

def create_folium_map(route=None):
    if not route:
        logger.info("Creating empty map")
        center_lat, center_lon, zoom_start = 20, 0, 2
    else:
        if not all(coord.get('latitude') and coord.get('longitude') for coord in route):
            logger.error("Invalid coordinates in route, creating default map")
            center_lat, center_lon, zoom_start = 20, 0, 2
        else:
            center_lat = sum(coord['latitude'] for coord in route) / len(route)
            center_lon = sum(coord['longitude'] for coord in route) / len(route)
            zoom_start = 4
    m = folium.Map(location=[center_lat, center_lon], zoom_start=zoom_start, tiles=None)
    folium.TileLayer(
        tiles='openstreetmap',
        attr='OpenStreetMap',
        name='OpenStreetMap',
        overlay=False,
        control=True
    ).add_to(m)
    proxy_tiles = '/proxy/tiles/{z}/{x}/{y}.png'
    try:
        folium.TileLayer(
            tiles=proxy_tiles,
            attr='OpenAIP',
            name='Aeronautical Chart',
            overlay=True,
            control=True,
            max_zoom=15,
            min_zoom=7,
            opacity=0.7
        ).add_to(m)
        logger.info("Aeronautical chart layer added successfully")
    except Exception as e:
        logger.error(f"Failed to add aeronautical chart layer: {e}")
    if route and all(coord.get('latitude') and coord.get('longitude') for coord in route):
        folium.Marker(
            [route[0]['latitude'], route[0]['longitude']],
            popup="Departure",
            icon=folium.Icon(color='blue', icon='plane')
        ).add_to(m)
        for i, waypoint in enumerate(route[1:-1], 1):
            folium.Marker(
                [waypoint['latitude'], waypoint['longitude']],
                popup=f"Waypoint {i}",
                icon=folium.Icon(color='green', icon='flag')
            ).add_to(m)
        folium.Marker(
            [route[-1]['latitude'], route[-1]['longitude']],
            popup="Arrival",
            icon=folium.Icon(color='red', icon='plane')
        ).add_to(m)
        route_points = [(coord['latitude'], coord['longitude']) for coord in route]
        folium.PolyLine(route_points, color="blue", weight=2.5, opacity=1).add_to(m)
    folium.LayerControl().add_to(m)
    return m._repr_html_()

def get_auth_data(given_username):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (given_username,))
            row = cursor.fetchone()
            return row['password_hash'] if row else ""
    except Exception as e:
        logger.error(f"Error loading auth data for {given_username}: {e}")
        return ""

def get_user_data(username):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, profile_picture FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                user_data = dict(user)
                logger.debug(f"Loaded user data for {username}: {user_data}")
                return user_data
            logger.warning(f"No user found for {username}, returning default data")
            return {'username': username, 'profile_picture': None}
    except Exception as e:
        logger.error(f"Error loading user data for {username}: {e}")
        return {'username': username, 'profile_picture': None}

def load_tail_numbers():
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT tail_number FROM tailnumbers")
            tail_numbers = [row['tail_number'] for row in cursor.fetchall()]
        logger.info(f"Loaded {len(tail_numbers)} tail numbers")
        return tail_numbers
    except Exception as e:
        logger.error(f"Error loading tail numbers: {e}")
        return ['N12345', 'N67890', 'N54321']

def load_user_routes(username):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, tail_number, departure, waypoints, arrival, time_departing, timestamp
                FROM flight_plans WHERE username = ?
            """, (username,))
            routes = [dict(row) for row in cursor.fetchall()]
        logger.info(f"Loaded {len(routes)} routes for {username}")
        return routes
    except Exception as e:
        logger.error(f"Error loading routes for {username}: {e}")
        return []

def save_route(username, routes):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            if isinstance(routes, list):
                for route in routes:
                    cursor.execute("""
                        INSERT INTO flight_plans (username, tail_number, departure, waypoints, arrival, time_departing, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        username,
                        route['tail_number'],
                        route['departure'],
                        route['waypoints'],
                        route['arrival'],
                        route['time_departing'],
                        datetime.now().isoformat()
                    ))
            else:
                cursor.execute("""
                    INSERT INTO flight_plans (username, tail_number, departure, waypoints, arrival, time_departing, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    username,
                    routes['tail_number'],
                    routes['departure'],
                    routes['waypoints'],
                    routes['arrival'],
                    routes['time_departing'],
                    datetime.now().isoformat()
                ))
            conn.commit()
        logger.info(f"Saved route(s) for {username}")
    except Exception as e:
        logger.error(f"Error saving route(s) for {username}: {e}")
        raise

def process_uploaded_routes(file, username):
    if not file or not file.filename:
        logger.warning("No file provided for upload")
        return None, "No file uploaded"
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        logger.info(f"Saved uploaded file: {file_path}")
        file.stream.seek(0)
        stream = io.StringIO(file.stream.read().decode('utf-8', errors='ignore'))
        csv_reader = csv.DictReader(stream)
        required_fields = {'tail_number', 'departure', 'arrival'}
        if not required_fields.issubset(csv_reader.fieldnames):
            logger.error(f"CSV missing required fields: {required_fields}")
            return None, f"CSV must include columns: {', '.join(required_fields)}. File saved."
        routes = []
        tail_numbers = load_tail_numbers()
        invalid_rows = []
        for i, row in enumerate(csv_reader, 1):
            tail_number = row.get('tail_number', '').strip()
            departure = row.get('departure', '').strip().upper()
            arrival = row.get('arrival', '').strip().upper()
            if not all([tail_number, departure, arrival]):
                invalid_rows.append(f"Row {i}: Missing required fields")
                continue
            if tail_number not in tail_numbers:
                invalid_rows.append(f"Row {i}: Invalid tail number '{tail_number}'")
                continue
            if not get_coordinates(departure):
                invalid_rows.append(f"Row {i}: Invalid departure airport code '{departure}'")
                continue
            if not get_coordinates(arrival):
                invalid_rows.append(f"Row {i}: Invalid arrival airport code '{arrival}'")
                continue
            waypoints = row.get('waypoints', '').strip().upper()
            if waypoints:
                waypoint_codes = [code.strip() for code in waypoints.split(',')]
                for code in waypoint_codes:
                    if code and not get_coordinates(code):
                        invalid_rows.append(f"Row {i}: Invalid waypoint code '{code}'")
                        continue
            routes.append({
                'tail_number': tail_number,
                'departure': departure,
                'waypoints': waypoints,
                'arrival': arrival,
                'time_departing': row.get('time_departing', '')
            })
        if invalid_rows:
            logger.error(f"CSV errors: {'; '.join(invalid_rows)}")
            return None, f"Errors in CSV: {'; '.join(invalid_rows)}. File saved."
        if not routes:
            logger.warning("No valid routes found in uploaded CSV")
            return None, "No valid routes found in file. File saved."
        logger.info(f"Processed {len(routes)} valid routes from CSV")
        return routes, None
    except Exception as e:
        logger.error(f"Error processing uploaded file: {e}")
        return None, f"Invalid file format or error processing file: {e}. File saved."

def delete_route(username, route_id):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM flight_plans WHERE username = ? AND id = ?", (username, route_id))
            conn.commit()
        logger.info(f"Deleted route {id} for {username}")
    except Exception as e:
        logger.error(f"Error deleting route {id} for {username}: {e}")

def username_exists(username):
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            return bool(cursor.fetchone())
    except Exception as e:
        logger.error(f"Error checking username existence for {username}: {e}")
        return False

@app.route('/proxy/tiles/<int:z>/<int:x>/<int:y>.png')
def proxy_tiles(z, x, y):
    tile_url = OPENAIP_TILES.format(z=z, x=x, y=y)
    if OPENAIP_API_KEY:
        tile_url += f"?apiKey={OPENAIP_API_KEY}"
    try:
        response = requests.get(tile_url, timeout=5)
        response.raise_for_status()
        return Response(response.content, mimetype='image/png')
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch tile {tile_url}: {e}")
        transparent_pixel = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x00\x00\x02\x00\x01\xe2!\xbc\xce\x00\x00\x00\x00IEND\xaeB`\x82'
        return Response(transparent_pixel, mimetype='image/png', status=404)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            error = "Username and password are required."
        else:
            password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
            verified_hash = get_auth_data(username)
            if password_hash == verified_hash and verified_hash:
                session['logged_in'] = True
                session['username'] = username
                logger.info(f"User {username} logged in successfully")
                return redirect(url_for('index'))
            error = "Invalid username or password."
    return render_template('login.html', error=error)

@app.route('/request_account', methods=['GET', 'POST'])
def request_account():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            error = "Username and password are required."
        elif username_exists(username):
            error = "Username already exists."
        else:
            try:
                password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                                  (username, password_hash))
                    conn.commit()
                logger.info(f"Created account for username: {username}")
                return render_template('login.html', success="Account created successfully. Please log in.")
            except Exception as e:
                logger.error(f"Error creating account for {username}: {e}")
                error = "Failed to create account. Please try again."
    return render_template('request_account.html', error=error)

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'logged_in' not in session or not session['logged_in'] or 'username' not in session:
        logger.warning("Invalid session, redirecting to login")
        return redirect(url_for('login'))
    username = session['username']
    user_data = get_user_data(username)
    if not user_data:
        logger.error(f"No user data found for {username}, logging out")
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    tail_numbers = load_tail_numbers()
    map_html = create_folium_map()
    error = None
    route_display = None
    if request.method == 'POST':
        action = request.form.get('action')
        dest_airport = request.form.get('dest_airport', '').upper().strip()
        arrival_airport = request.form.get('arrival_airport', '').upper().strip()
        waypoints_input = request.form.get('waypoints', '').upper().strip()
        time_departing = request.form.get('time_departing', '')
        tail_number = request.form.get('tail_number', '').strip()
        if action == 'clear':
            return render_template('index.html', map_html=create_folium_map(), error=None, 
                                  tail_numbers=tail_numbers, route_display=None, username=username, user=user_data)
        if action == 'save' and all([dest_airport, arrival_airport, tail_number]):
            try:
                start_coords = get_coordinates(dest_airport)
                end_coords = get_coordinates(arrival_airport)
                if not start_coords or not end_coords:
                    error = f"Invalid airport code(s): '{dest_airport}' or '{arrival_airport}'."
                else:
                    save_route(username, {
                        'tail_number': tail_number,
                        'departure': dest_airport,
                        'waypoints': waypoints_input,
                        'arrival': arrival_airport,
                        'time_departing': time_departing
                    })
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
                    if not error:
                        route = optimize_route(start_coords, waypoints, end_coords)
                        map_html = create_folium_map(route)
                        route_display = f"{dest_airport} -> {waypoints_input + ', ' if waypoints_input else ''}{arrival_airport}"
            except Exception as e:
                logger.error(f"Error saving route for {username}: {e}")
                error = "An error occurred while saving the route."
        else:
            error = "Missing required fields: Tail number, departure, or arrival airport."
    return render_template('index.html', map_html=map_html, error=error, 
                          tail_numbers=tail_numbers, route_display=route_display, username=username, user=user_data)

@app.route('/routes', methods=['GET', 'POST'])
def routes():
    if 'logged_in' not in session or not session['logged_in'] or 'username' not in session:
        logger.warning("Invalid session, redirecting to login")
        return redirect(url_for('login'))
    username = session['username']
    user_data = get_user_data(username)
    if not user_data:
        logger.error(f"No user data found for {username}, logging out")
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    saved_routes = load_user_routes(username)
    error = None
    success = None
    if request.method == 'POST':
        if 'route' in request.form:
            selected_route = request.form.get('route')
            if selected_route:
                try:
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
                    map_html = create_folium_map(route_coords)
                    return render_template('index.html', map_html=map_html, error=None, 
                                          tail_numbers=load_tail_numbers(), route_display=None, 
                                          username=username, user=user_data)
                except (ValueError, IndexError) as e:
                    logger.error(f"Invalid route selection for {username}: {e}")
                    error = "Invalid route selected."
        elif 'delete' in request.form:
            delete_idx = request.form.get('delete')
            try:
                delete_route(username, delete_idx)
                saved_routes = load_user_routes(username)
                success = "Route deleted successfully."
            except Exception as e:
                logger.error(f"Error deleting route for {username}: {e}")
                error = "Failed to delete route."
        elif 'upload' in request.files:
            file = request.files['upload']
            routes_to_save, error = process_uploaded_routes(file, username)
            if routes_to_save:
                try:
                    save_route(username, routes_to_save)
                    saved_routes = load_user_routes(username)
                    success = f"Successfully uploaded {len(routes_to_save)} route(s)."
                except Exception as e:
                    logger.error(f"Error saving uploaded routes for {username}: {e}")
                    error = "Failed to save uploaded routes."
    return render_template('routes.html', routes=saved_routes, error=error, success=success, username=username, user=user_data)

@app.route('/account')
def account():
    if 'logged_in' not in session or not session['logged_in'] or 'username' not in session:
        logger.warning("Invalid session, redirecting to login")
        return redirect(url_for('login'))
    username = session['username']
    user_data = get_user_data(username)
    if not user_data:
        logger.error(f"No user data found for {username}, logging out")
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    return render_template('account.html', username=username, user=user_data)

@app.route('/edit_account', methods=['GET', 'POST'])
def edit_account():
    if 'logged_in' not in session or not session['logged_in'] or 'username' not in session:
        logger.warning("Invalid session, redirecting to login")
        return redirect(url_for('login'))
    username = session['username']
    user_data = get_user_data(username)
    if not user_data:
        logger.error(f"No user data found for {username}, logging out")
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    error = None
    success = None
    if request.method == 'POST':
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename == '':
                error = "No file selected."
            elif file:
                filename = secure_filename(file.filename)
                unique_filename = f"{username}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                try:
                    file.save(file_path)
                    if filename.endswith('.py'):
                        os.chmod(file_path, 0o755)
                        subprocess.Popen(['python3', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        logger.debug(f"Processed script upload for {username}: {unique_filename}")
                    with get_db() as conn:
                        cursor = conn.cursor()
                        cursor.execute("UPDATE users SET profile_picture = ? WHERE username = ?", 
                                      (unique_filename, username))
                        conn.commit()
                    user_data['profile_picture'] = unique_filename
                    success = "Profile picture updated successfully."
                    logger.info(f"Updated profile picture for {username}: {unique_filename}")
                except Exception as e:
                    logger.error(f"Error updating profile picture for {username}: {e}")
                    error = "Failed to update profile picture."
            else:
                error = "No file provided."
    return render_template('edit_account.html', username=username, user=user_data, error=error, success=success)

@app.route('/Uploads/<filename>')
def uploaded_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    logger.info(f"Attempting to access file: {file_path}")
    if os.path.exists(file_path):
        logger.info(f"File found: {file_path}")
        try:
            if filename.endswith(('.png', '.jpg', '.jpeg')):
                return send_file(file_path, mimetype='image/' + filename.rsplit('.', 1)[1].lower())
            elif filename.endswith('.csv'):
                return send_file(file_path, mimetype='text/csv')
            else:
                return send_file(file_path, mimetype='application/octet-stream')
        except Exception as e:
            logger.error(f"Error serving {file_path}: {e}")
            return f"Error serving file: {e}", 500
    logger.error(f"File not found: {file_path}")
    return "File not found.", 404

@app.route('/export_routes')
def export_routes():
    if 'logged_in' not in session or not session['logged_in'] or 'username' not in session:
        logger.warning("Invalid session, redirecting to login")
        return redirect(url_for('login'))
    username = session['username']
    user_data = get_user_data(username)
    if not user_data:
        logger.error(f"No user data found for {username}, logging out")
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    saved_routes = load_user_routes(username)
    if not saved_routes:
        logger.info(f"No routes to export for {username}")
        return render_template('routes.html', routes=[], error="No routes to export.", username=username, user=user_data)
    try:
        output = io.StringIO()
        fieldnames = ['username', 'tail_number', 'departure', 'waypoints', 'arrival', 'time_departing', 'timestamp']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for route in saved_routes:
            writer.writerow(route)
        output.seek(0)
        logger.info(f"Exported {len(saved_routes)} routes for {username}")
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"{username}_routes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
    except Exception as e:
        logger.error(f"Error exporting routes for {username}: {e}")
        return render_template('routes.html', routes=saved_routes, error="An error occurred while exporting routes.", 
                              username=username, user=user_data)

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    logger.info(f"User {username} logged out")
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=12344)
