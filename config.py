import os
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'Data')
AIRPORTS_CSV = os.path.join(DATA_DIR, 'airports.csv')
AUTH_CSV = os.path.join(DATA_DIR, 'authenticate.csv')
TAILNUMBERS_CSV = os.path.join(DATA_DIR, 'tailnumbers.csv')
FLIGHT_PLANS_CSV = os.path.join(DATA_DIR, 'flight_plans.csv')
OPENAIP_TILES = 'https://a.api.tiles.openaip.net/api/data/openaip/{z}/{x}/{y}.png'
OPENAIP_API_KEY = os.getenv('OPENAIP_API_KEY') or '447847231b754a78e6e70354f2a3365a'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'Uploads')

# Ensure UPLOAD_FOLDER exists and is writable
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    os.chmod(UPLOAD_FOLDER, 0o775)  # Ensure directory is writable
