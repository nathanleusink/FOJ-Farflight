##
# Author: 1st Lt Nathan Leusink
# SOURCE: https://ourairports.com/data/
##

# Imports
from flask import Flask, render_template, request, redirect, url_for, session, Response, send_file
import folium
import pandas as pd
import os
from math import radians, sin, cos, sqrt, atan2
import hashlib
import requests
import logging
import secrets
from dotenv import load_dotenv
import csv
from datetime import datetime
import io

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Determine the base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Flask app setup
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configuration
DATA_DIR = os.path.join(BASE_DIR, 'Data')
AIRPORTS_CSV = os.path.join(DATA_DIR, 'airports.csv')
AUTH_CSV = os.path.join(DATA_DIR, 'authenticate.csv')
TAILNUMBERS_CSV = os.path.join(DATA_DIR, 'tailnumbers.csv')
FLIGHT_PLANS_CSV = os.path.join(DATA_DIR, 'flight_plans.csv')
OPENAIP_TILES = 'https://a.api.tiles.openaip.net/api/data/openaip/{z}/{x}/{y}.png'
OPENAIP_API_KEY = os.getenv('OPENAIP_API_KEY') or '447847231b754a78e6e70354f2a3365a'

# Haversine formula for distance calculation
def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

# Load airport data from CSV
def load_airport_data():
    logger.info("Loading airport data...")
    try:
        if not os.path.exists(AIRPORTS_CSV):
            raise FileNotFoundError(f"'{AIRPORTS_CSV}' not found")
        airports_df = pd.read_csv(AIRPORTS_CSV, quotechar='"', encoding='utf-8')
        if airports_df.empty:
            raise ValueError(f"'{AIRPORTS_CSV}' is empty")

        coordinates = {}
        for _, row in airports_df.iterrows():
            iata_code = row[12]  # IATA code (column 13, 0-indexed)
            latitude = row[4]    # latitude_deg (column 5)
            longitude = row[5]   # longitude_deg (column 6)
            if pd.notna(iata_code) and pd.notna(latitude) and pd.notna(longitude):
                coordinates[iata_code] = {'latitude': float(latitude), 'longitude': float(longitude)}
        
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
    logger.debug(f"Looking up {airport_code}: {result}")
    return result

def optimize_route(start_coords, waypoints, end_coords):
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

def create_map(route=None):
    center_lat, center_lon = (20, 0) if not route else (
        sum(coord['latitude'] for coord in route) / len(route),
        sum(coord['longitude'] for coord in route) / len(route)
    )
    zoom_start = 2 if not route else 4
    
    m = folium.Map(location=[center_lat, center_lon], zoom_start=zoom_start, tiles=None)
    
    logger.debug("Adding OpenStreetMap base layer")
    folium.TileLayer(
        tiles='openstreetmap',
        attr='OpenStreetMap',
        name='OpenStreetMap',
        overlay=False,
        control=True
    ).add_to(m)
    
    proxy_tiles = '/proxy/tiles/{z}/{x}/{y}.png'
    logger.debug(f"Adding OpenAIP tile layer with proxy URL: {proxy_tiles}")
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
    
    if route:
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

# Load tail numbers from CSV
def load_tail_numbers():
    tail_numbers = []
    try:
        with open(TAILNUMBERS_CSV, 'r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if row:  # Check if row is not empty
                    tail_numbers.append(row[0])
        logger.info(f"Loaded {len(tail_numbers)} tail numbers")
    except FileNotFoundError:
        logger.error(f"'{TAILNUMBERS_CSV}' not found. Using dummy data.")
        tail_numbers = ['N12345', 'N67890', 'N54321']
    except Exception as e:
        logger.error(f"Error loading tail numbers: {e}")
        tail_numbers = ['N12345', 'N67890', 'N54321']
    return tail_numbers

# Load saved routes for a user from flight_plans.csv
def load_user_routes(username):
    routes = []
    try:
        if os.path.exists(FLIGHT_PLANS_CSV):
            with open(FLIGHT_PLANS_CSV, 'r') as file:
                csv_reader = csv.DictReader(file)
                for row in csv_reader:
                    if row['username'] == username:
                        routes.append(row)
    except Exception as e:
        logger.error(f"Error loading routes: {e}")
    return routes

# Save a route or multiple routes to flight_plans.csv
def save_route(username, routes):
    fieldnames = ['username', 'tail_number', 'departure', 'waypoints', 'arrival', 'time_departing', 'timestamp']
    file_exists = os.path.exists(FLIGHT_PLANS_CSV)
    try:
        with open(FLIGHT_PLANS_CSV, 'a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            if isinstance(routes, list):
                for route in routes:
                    route_data = {
                        'username': username,
                        'tail_number': route['tail_number'],
                        'departure': route['departure'],
                        'waypoints': route['waypoints'],
                        'arrival': route['arrival'],
                        'time_departing': route['time_departing'],
                        'timestamp': datetime.now().isoformat()
                    }
                    writer.writerow(route_data)
                    logger.info(f"Saved route for {username}: {route['tail_number']}, {route['departure']} -> {route['arrival']}")
            else:
                route_data = {
                    'username': username,
                    'tail_number': routes['tail_number'],
                    'departure': routes['departure'],
                    'waypoints': routes['waypoints'],
                    'arrival': routes['arrival'],
                    'time_departing': routes['time_departing'],
                    'timestamp': datetime.now().isoformat()
                }
                writer.writerow(route_data)
                logger.info(f"Saved route for {username}: {routes['tail_number']}, {routes['departure']} -> {routes['arrival']}")
    except Exception as e:
        logger.error(f"Error saving route(s): {e}")
        raise

# Process uploaded file
def process_uploaded_routes(file, username):
    if not file:
        return None, "No file uploaded"
    
    try:
        # Read the file as CSV
        stream = io.StringIO(file.stream.read().decode('utf-8', errors='ignore'))
        csv_reader = csv.DictReader(stream)
        
        required_fields = ['tail_number', 'departure', 'arrival']
        if not all(field in csv_reader.fieldnames for field in required_fields):
            return None, f"CSV must include columns: {', '.join(required_fields)}"
        
        routes = []
        tail_numbers = load_tail_numbers()
        invalid_rows = []
        for i, row in enumerate(csv_reader, 1):
            # Validate required fields
            if not all(row.get(field) for field in required_fields):
                invalid_rows.append(f"Row {i}: Missing required fields")
                continue
            
            # Validate tail number
            if row['tail_number'] not in tail_numbers:
                invalid_rows.append(f"Row {i}: Invalid tail number '{row['tail_number']}'")
                continue
            
            # Validate airport codes
            if not get_coordinates(row['departure']):
                invalid_rows.append(f"Row {i}: Invalid departure airport code '{row['departure']}'")
                continue
            if not get_coordinates(row['arrival']):
                invalid_rows.append(f"Row {i}: Invalid arrival airport code '{row['arrival']}'")
                continue
            
            # Validate waypoints (if provided)
            waypoints = row.get('waypoints', '').strip()
            if waypoints:
                waypoint_codes = [code.strip() for code in waypoints.split(',')]
                for code in waypoint_codes:
                    if code and not get_coordinates(code):
                        invalid_rows.append(f"Row {i}: Invalid waypoint code '{code}'")
                        continue
            
            routes.append({
                'tail_number': row['tail_number'],
                'departure': row['departure'],
                'waypoints': waypoints,
                'arrival': row['arrival'],
                'time_departing': row.get('time_departing', '')
            })
        
        if invalid_rows:
            return None, f"Errors in CSV: {'; '.join(invalid_rows)}"
        
        if not routes:
            return None, "No valid routes found in file"
        
        return routes, None
    except Exception as e:
        logger.error(f"Error processing uploaded file: {e}")
        return None, "Invalid file format or error processing file"

# Delete a route from flight_plans.csv
def delete_route(username, route_index):
    try:
        if not os.path.exists(FLIGHT_PLANS_CSV):
            return
        # Read all routes
        with open(FLIGHT_PLANS_CSV, 'r') as file:
            csv_reader = csv.DictReader(file)
            all_routes = list(csv_reader)
        
        # Filter out the route to delete
        user_routes = [r for r in all_routes if r['username'] == username]
        if route_index < 0 or route_index >= len(user_routes):
            logger.error(f"Invalid route index: {route_index}")
            return
        
        route_to_delete = user_routes[route_index]
        all_routes = [r for r in all_routes if r != route_to_delete]
        
        # Rewrite the CSV without the deleted route
        with open(FLIGHT_PLANS_CSV, 'w', newline='') as file:
            fieldnames = ['username', 'tail_number', 'departure', 'waypoints', 'arrival', 'time_departing', 'timestamp']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_routes)
        logger.info(f"Deleted route for {username} at index {route_index}")
    except Exception as e:
        logger.error(f"Error deleting route: {e}")

# Check if username already exists
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

# Proxy route for OpenAIP tiles with API key integration
@app.route('/proxy/tiles/<int:z>/<int:x>/<int:y>.png')
def proxy_tiles(z, x, y):
    tile_url = OPENAIP_TILES.format(z=z, x=x, y=y)
    if OPENAIP_API_KEY:
        tile_url += f"?apiKey={OPENAIP_API_KEY}"
    logger.debug(f"Requesting tile from OpenAIP: {tile_url}")
    try:
        response = requests.get(tile_url, timeout=5)
        response.raise_for_status()
        logger.debug(f"Successfully fetched tile: {tile_url}")
        return Response(response.content, mimetype='image/png')
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch tile {tile_url}: {e}")
        transparent_pixel = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x00\x00\x02\x00\x01\xe2!\xbc\xce\x00\x00\x00\x00IEND\xaeB`\x82'
        return Response(transparent_pixel, mimetype='image/png', status=404)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
        verified_hash = get_auth_data(username)
        
        if password_hash == verified_hash and verified_hash:
            session['logged_in'] = True
            session['username'] = username  # Store username in session
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html', error=None)

# Request account route
@app.route('/request_account', methods=['GET', 'POST'])
def request_account():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template('request_account.html', error="Username and password are required")
        
        if username_exists(username):
            return render_template('request_account.html', error="Username already exists")
        
        # Hash the password and save to authenticate.csv
        try:
            password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
            with open(AUTH_CSV, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([username, password_hash])
            logger.info(f"Created account for username: {username}")
            return render_template('login.html', success="Account created successfully. Please log in.")
        except Exception as e:
            logger.error(f"Error creating account: {e}")
            return render_template('request_account.html', error="Failed to create account. Please try again.")
    
    return render_template('request_account.html', error=None)

# Main route
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    
    username = session.get('username', 'unknown')
    tail_numbers = load_tail_numbers()
    map_html = create_map()
    error = None
    route_display = None  # To store route text for display
    
    if request.method == 'POST':
        action = request.form.get('action')
        dest_airport = request.form.get('dest_airport', '').upper()
        arrival_airport = request.form.get('arrival_airport', '').upper()
        waypoints_input = request.form.get('waypoints', '').upper()
        time_departing = request.form.get('time_departing', '')
        tail_number = request.form.get('tail_number', '')
        
        if action == 'clear':
            # Clear the route by rendering the default map
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
            # After saving, still display the route
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
            # Format the route for display (e.g., "JFK -> ORD, DEN -> LAX")
            route_display = f"{dest_airport} -> {waypoints_input + ', ' if waypoints_input else ''}{arrival_airport}"
    
    return render_template('index.html', map_html=map_html, error=error, 
                         tail_numbers=tail_numbers, route_display=route_display)

# Routes page
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
                return render_template('index.html', map_html=map_html, error=None, tail_numbers=load_tail_numbers())
        elif 'delete' in request.form:
            delete_idx = int(request.form.get('delete'))
            delete_route(username, delete_idx)
            saved_routes = load_user_routes(username)  # Refresh routes after deletion
            success = "Route deleted successfully"
        elif 'upload' in request.files:
            file = request.files['upload']
            routes_to_save, error = process_uploaded_routes(file, username)
            if routes_to_save:
                try:
                    save_route(username, routes_to_save)
                    saved_routes = load_user_routes(username)  # Refresh routes
                    success = f"Successfully uploaded {len(routes_to_save)} route(s)"
                except Exception:
                    error = "Failed to save uploaded routes"
    
    return render_template('routes.html', routes=saved_routes, error=error, success=success)

# Export routes as CSV
@app.route('/export_routes')
def export_routes():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    
    username = session.get('username', 'unknown')
    saved_routes = load_user_routes(username)
    
    if not saved_routes:
        return redirect(url_for('routes', error="No routes to export"))
    
    # Create CSV in memory
    output = io.StringIO()
    fieldnames = ['username', 'tail_number', 'departure', 'waypoints', 'arrival', 'time_departing', 'timestamp']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for route in saved_routes:
        writer.writerow(route)
    
    # Prepare response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"{username}_routes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

# Logout route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=12344)
