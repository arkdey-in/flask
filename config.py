import os
from dotenv import load_dotenv

load_dotenv()

# Flask Config
SECRET_KEY = os.getenv('SECRET_KEY')

# Database Config
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

# File Upload Config
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'pdf,png,jpg,jpeg').split(','))
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 20971520))

# API Keys (will be loaded from environment variables)
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
AZURE_DI_ENDPOINT = os.getenv('AZURE_DI_ENDPOINT')
AZURE_DI_KEY = os.getenv('AZURE_DI_KEY')
AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY')
AWS_S3_BUCKET = os.getenv('AWS_S3_BUCKET')
AWS_REGION = os.getenv('AWS_REGION')