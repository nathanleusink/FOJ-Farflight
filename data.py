import pandas as pd
import os
import csv
from datetime import datetime
import io
import logging
from config import AIRPORTS_CSV, AUTH_CSV, TAILNUMBERS_CSV, FLIGHT_PLANS_CSV

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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
            iata_code = row[12]
            latitude = row[4]
            longitude = row[5]
            if pd.notna(iata_code) and pd.notna(latitude) and pd.notna(longitude):
                coordinates[iata_code] = {'latitude': float(latitude), 'longitude': float(longitude)}
        logger.info(f"Loaded {len(coordinates)} airports")
        return coordinates
    except Exception as e:
        logger.error(f"Error loading airport data: {e}")
        return {}

airport_coordinates = load_airport_data()

def get_coordinates(airport_code):
    result = airport_coordinates.get(airport_code.upper())
    logger.debug(f"Looking up {airport_code}: {result}")
    return result

def load_tail_numbers():
    tail_numbers = []
    try:
        with open(TAILNUMBERS_CSV, 'r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if row:
                    tail_numbers.append(row[0])
        logger.info(f"Loaded {len(tail_numbers)} tail numbers")
    except FileNotFoundError:
        logger.error(f"'{TAILNUMBERS_CSV}' not found. Using dummy data.")
        tail_numbers = ['N12345', 'N67890', 'N54321']
    except Exception as e:
        logger.error(f"Error loading tail numbers: {e}")
        tail_numbers = ['N12345', 'N67890', 'N54321']
    return tail_numbers

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

def process_uploaded_routes(file, username):
    if not file:
        return None, "No file uploaded"
    try:
        stream = io.StringIO(file.stream.read().decode('utf-8', errors='ignore'))
        csv_reader = csv.DictReader(stream)
        required_fields = ['tail_number', 'departure', 'arrival']
        if not all(field in csv_reader.fieldnames for field in required_fields):
            return None, f"CSV must include columns: {', '.join(required_fields)}"
        routes = []
        tail_numbers = load_tail_numbers()
        invalid_rows = []
        for i, row in enumerate(csv_reader, 1):
            if not all(row.get(field) for field in required_fields):
                invalid_rows.append(f"Row {i}: Missing required fields")
                continue
            if row['tail_number'] not in tail_numbers:
                invalid_rows.append(f"Row {i}: Invalid tail number '{row['tail_number']}'")
                continue
            if not get_coordinates(row['departure']):
                invalid_rows.append(f"Row {i}: Invalid departure airport code '{row['departure']}'")
                continue
            if not get_coordinates(row['arrival']):
                invalid_rows.append(f"Row {i}: Invalid arrival airport code '{row['arrival']}'")
                continue
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

def delete_route(username, route_index):
    try:
        if not os.path.exists(FLIGHT_PLANS_CSV):
            return
        with open(FLIGHT_PLANS_CSV, 'r') as file:
            csv_reader = csv.DictReader(file)
            all_routes = list(csv_reader)
        user_routes = [r for r in all_routes if r['username'] == username]
        if route_index < 0 or route_index >= len(user_routes):
            logger.error(f"Invalid route index: {route_index}")
            return
        route_to_delete = user_routes[route_index]
        all_routes = [r for r in all_routes if r != route_to_delete]
        with open(FLIGHT_PLANS_CSV, 'w', newline='') as file:
            fieldnames = ['username', 'tail_number', 'departure', 'waypoints', 'arrival', 'time_departing', 'timestamp']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_routes)
        logger.info(f"Deleted route for {username} at index {route_index}")
    except Exception as e:
        logger.error(f"Error deleting route: {e}")
