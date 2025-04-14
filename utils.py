import folium
from math import radians, sin, cos, sqrt, atan2
import requests
import logging
from config import OPENAIP_TILES, OPENAIP_API_KEY

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Haversine formula for distance calculation
def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

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

def proxy_tiles(z, x, y):
    tile_url = OPENAIP_TILES.format(z=z, x=x, y=y)
    if OPENAIP_API_KEY:
        tile_url += f"?apiKey={OPENAIP_API_KEY}"
    logger.debug(f"Requesting tile from OpenAIP: {tile_url}")
    try:
        response = requests.get(tile_url, timeout=5)
        response.raise_for_status()
        logger.debug(f"Successfully fetched tile: {tile_url}")
        return response.content, 'image/png', 200
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch tile {tile_url}: {e}")
        transparent_pixel = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x00\x00\x02\x00\x01\xe2!\xbc\xce\x00\x00\x00\x00IEND\xaeB`\x82'
        return transparent_pixel, 'image/png', 404