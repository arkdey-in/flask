# --- Core Flask and Form Imports ---
from flask import (
    Blueprint,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    request,
    current_app,
    send_from_directory,
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    ValidationError,
    EqualTo,
    Length,
    Regexp,
)
from werkzeug.security import generate_password_hash, check_password_hash
import re
from functools import wraps
import bcrypt

# --- Stdlib / Utils ---
import os
import json
import uuid
import tempfile
import shutil
import subprocess
import glob

# --- OCR / AI / Files ---
import pytesseract
from PIL import Image
import magic
import openai
from PyPDF2 import PdfReader, PdfWriter
from werkzeug.utils import secure_filename

# Azure SDK
from azure.core.credentials import AzureKeyCredential
from azure.ai.documentintelligence import DocumentIntelligenceClient
from azure.core.exceptions import (
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)

# S3 / Database
import boto3
from botocore.exceptions import ClientError
import pymysql.cursors
import pymysql.err
from datetime import datetime, timedelta


# --- Blueprint Definition ---
main = Blueprint("main", __name__)


# ---------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------

# S3 client and functions
# def get_s3_client():
#     """Initializes and returns the Boto3 S3 client using app config."""
#     return boto3.client(
#         "s3",
#         aws_access_key_id=current_app.config.get("AWS_ACCESS_KEY"),
#         aws_secret_access_key=current_app.config.get("AWS_SECRET_KEY"),
#         region_name=current_app.config.get("AWS_REGION"),
#     )


def get_s3_client():
    """
    Initializes and returns the Boto3 S3 client.
    It will automatically use the IAM Role when running on EC2.
    """
    return boto3.client(
        "s3",
        region_name=current_app.config.get("AWS_REGION")
    )
# def upload_file_to_s3(file, bucket_name, acl="public-read"):
#     """Uploads a file object to S3."""
#     s3_client = get_s3_client()
#     try:
#         s3_client.upload_fileobj(
#             file,  # This is the file object
#             bucket_name,
#             file.filename,
#             ExtraArgs={
#                 "ACL": acl,
#                 "ContentType": file.content_type
#             }
#         )
#         # Generate the URL
#         aws_region = current_app.config.get("AWS_REGION")
#         url = f"https://{bucket_name}.s3.{aws_region}.amazonaws.com/{file.filename}"
#         return url
#     except ClientError as e:
#         print(f"Error uploading to S3: {e}")
#         return None


# def upload_file_to_s3(file_obj, bucket_name, object_name, acl="public-read"): # CHANGED: Added object_name
#     """Uploads a file object to S3."""
#     s3_client = get_s3_client()
#     try:
#         # Get the content type from the file object if it exists
#         content_type = getattr(file_obj, 'content_type', 'application/octet-stream')
        
#         s3_client.upload_fileobj(
#             file_obj,       # This is the file object
#             bucket_name,
#             object_name,    # CHANGED: Use the provided object_name
#             ExtraArgs={
#                 "ACL": acl,
#                 "ContentType": content_type
#             }
#         )
#         # Generate the URL
#         aws_region = current_app.config.get("AWS_REGION")
#         url = f"https://{bucket_name}.s3.{aws_region}.amazonaws.com/{object_name}" # CHANGED: Use object_name
#         return url
#     except ClientError as e:
#         current_app.logger.error(f"Error uploading to S3: {e}")
#         return None

def upload_file_to_s3(file_obj, bucket_name, object_name):
    """Uploads a file object to S3."""
    s3_client = get_s3_client()
    try:
        content_type = getattr(file_obj, 'content_type', 'application/octet-stream')

        s3_client.upload_fileobj(
            file_obj,
            bucket_name,
            object_name,
            ExtraArgs={
                "ContentType": content_type
            } # The "ACL" argument has been removed
        )

        aws_region = current_app.config.get("AWS_REGION")
        url = f"https://{bucket_name}.s3.{aws_region}.amazonaws.com/{object_name}"
        return url
    except ClientError as e:
        current_app.logger.error(f"Error uploading to S3: {e}")
        return None
    
    
def delete_file_from_s3(key, bucket_name):
    """Deletes a file from S3 using its key (filename)."""
    s3_client = get_s3_client()
    try:
        s3_client.delete_object(Bucket=bucket_name, Key=key)
        return True
    except ClientError as e:
        current_app.logger.error(f"Error deleting file from S3: {e}")
        return False

def get_db_connection():
    """Establishes and returns a database connection using app config."""
    return pymysql.connect(
        host=current_app.config.get("DB_HOST"),
        user=current_app.config.get("DB_USER"),
        password=current_app.config.get("DB_PASSWORD"),
        database=current_app.config.get("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
    )

def get_client_ip():
    """Gets the client's IP address, handling proxies."""
    if "X-Forwarded-For" in request.headers:
        forwarded_ips = request.headers["X-Forwarded-For"].split(",")
        client_ip = forwarded_ips[0].strip()
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", client_ip):
            client_ip = request.remote_addr
    else:
        client_ip = request.remote_addr
    return client_ip

def log_user_activity(user_id, user_name, user_type, event_type, model, value):
    """Logs user activity to the unified user_activities table."""
    connection = get_db_connection()
    try:
        client_ip = get_client_ip()
        with connection.cursor() as cursor:
            sql = """
            INSERT INTO user_activities
            (user_id, user_name, user_type, user_ip, event_type, model, value)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                sql, (user_id, user_name, user_type, client_ip, event_type, model, value)
            )
        connection.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log user activity: {e}")
        connection.rollback()
    finally:
        connection.close()


def get_azure_client():
    """Initializes and returns the Azure Document Intelligence client."""
    endpoint = current_app.config.get("AZURE_DI_ENDPOINT")
    key = current_app.config.get("AZURE_DI_KEY")
    if not endpoint or not key:
        return None
    return DocumentIntelligenceClient(
        endpoint=endpoint, credential=AzureKeyCredential(key)
    )

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in current_app.config["ALLOWED_EXTENSIONS"]
    )

def compress_image(image_path, quality=85):
    """Compresses an image file."""
    try:
        with Image.open(image_path) as img:
            if img.format == "PNG":
                img = img.convert("RGBA")
            img.save(image_path, optimize=True, quality=quality)
        return True
    except Exception as e:
        print(f"Error compressing image {image_path}: {e}")
        return False


def get_file_content_as_bytes(filepath):
    """Reads file content as bytes."""
    with open(filepath, "rb") as f:
        return f.read()

def get_pdf_page_count(filepath):
    """Gets the number of pages in a PDF file."""
    try:
        with open(filepath, "rb") as f:
            reader = PdfReader(f)
            return len(reader.pages)
    except Exception as e:
        current_app.logger.error(f"Could not read PDF page count for {filepath}: {e}")
        return 0

def does_superadmin_exist():
    """Checks the DB and returns True if a superadmin exists, False otherwise."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            #  use "SELECT 1" because it's the most efficient way to check for existence
            cursor.execute("SELECT 1 FROM superadmin LIMIT 1")
            result = cursor.fetchone()
            # If fetchone() finds a row, result is not None, so return True
            return result is not None
    except Exception as e:
        # Log the error and assume the worst case (don't allow registration)
        current_app.logger.error(f"Database error checking for superadmin: {e}")
        return True # Fail-safe
    finally:
        connection.close()

@main.context_processor
def inject_registration_status():
    """Injects a variable into all templates to show/hide the registration link."""
    # The variable will be True if registration is allowed (no superadmin exists)
    # and False if it's disabled.
    registration_enabled = not does_superadmin_exist()
    return dict(registration_enabled=registration_enabled)
# ---------------------------------------------------------------------
# Tesseract OCR (fallback / image-only PDFs)
# ---------------------------------------------------------------------

def perform_tesseract_ocr(filepath, mime_type):
    """
    Performs OCR on a PDF by converting it to images via Poppler and then
    processing the images with Tesseract. Works on all pages.
    Paths are configurable via:
      - POPPLER_PATH (dir containing pdfinfo/pdftoppm)
      - TESSERACT_CMD (full path to tesseract binary)
    """
    full_text = ""
    temp_dir = tempfile.mkdtemp(prefix="temp_images_")

    poppler_bin_path = (
        current_app.config.get("POPPLER_PATH")
        or os.getenv("POPPLER_PATH")
        or "/usr/bin"
    )
    tesseract_path = (
        current_app.config.get("TESSERACT_CMD")
        or os.getenv("TESSERACT_CMD")
        or "tesseract"
    )

    try:
        pytesseract.pytesseract.tesseract_cmd = tesseract_path

        if mime_type == "application/pdf":
            current_app.logger.info(f"[Tesseract] Converting PDF: {filepath}")

            pdfinfo_command = os.path.join(poppler_bin_path, "pdfinfo")
            pdftoppm_command = os.path.join(poppler_bin_path, "pdftoppm")

            # Determine number of pages
            result = subprocess.run(
                [pdfinfo_command, filepath], capture_output=True, text=True
            )
            num_pages = 0
            for line in result.stdout.splitlines():
                if line.strip().startswith("Pages:"):
                    num_pages = int(line.split(":")[1].strip())
                    break
            if num_pages == 0:
                raise ValueError("Could not determine the number of pages in the PDF.")

            for page_num in range(1, num_pages + 1):
                output_prefix = os.path.join(temp_dir, f"page_{page_num}")
                command = [
                    pdftoppm_command,
                    "-png",
                    "-f",
                    str(page_num),
                    "-l",
                    str(page_num),
                    "-r",
                    "300",
                    filepath,
                    output_prefix,
                ]
                result = subprocess.run(command, capture_output=True, text=True)
                if result.returncode != 0:
                    current_app.logger.error(
                        f"[Tesseract] pdftoppm failed on page {page_num}: {result.stderr}"
                    )
                    continue

                image_files = sorted(glob.glob(f"{output_prefix}-*.png"))
                if not image_files:
                    current_app.logger.warning(
                        f"[Tesseract] No image files generated for page {page_num}."
                    )
                    continue

                for idx, image_file in enumerate(image_files, 1):
                    try:
                        with Image.open(image_file) as img:
                            page_text = pytesseract.image_to_string(img)
                        full_text += f"--- Page {page_num}.{idx} ---\n{page_text}\n\n"
                        os.remove(image_file)
                    except Exception as e:
                        current_app.logger.error(
                            f"[Tesseract] Error reading image {image_file}: {e}"
                        )
        else:
            with Image.open(filepath) as im:
                full_text = pytesseract.image_to_string(im)

    except Exception as e:
        current_app.logger.exception(f"[Tesseract] OCR Error: {e}")
        raise ConnectionError(f"OCR failed: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return full_text


# ---------------------------------------------------------------------
# Azure OCR (fast: whole-file; fallback: chunked & parallel)
# ---------------------------------------------------------------------


# AFTER (The correct code)
# def _azure_analyze_file(client, model_id, file_path_or_bytes):
#     """
#     Calls Azure DI Read/Layout and returns the result object.
#     Accepts either bytes or a path to keep memory usage predictable on big docs.
#     """
#     if isinstance(file_path_or_bytes, (bytes, bytearray)):
#         poller = client.begin_analyze_document(
#             model_id=model_id,
#             document=file_path_or_bytes,  # <--- CORRECTED
#             content_type="application/pdf",
#         )
#     else:
#         with open(file_path_or_bytes, "rb") as f:
#             poller = client.begin_analyze_document(
#                 model_id=model_id,
#                 document=f,  # <--- CORRECTED
#                 content_type="application/pdf",
#             )
#     return poller.result()


# REPLACE the entire function with this one
def _azure_analyze_file(client, model_id, file_path_or_bytes):
    """
    Calls Azure DI Read/Layout and returns the result object.
    """
    if isinstance(file_path_or_bytes, (bytes, bytearray)):
        poller = client.begin_analyze_document(
            model_id=model_id,
            body=file_path_or_bytes, # Use 'body' as the new error requests
            content_type="application/pdf",
        )
    else:
        with open(file_path_or_bytes, "rb") as f:
            poller = client.begin_analyze_document(
                model_id=model_id,
                body=f, # Use 'body' as the new error requests
                content_type="application/pdf",
            )
    return poller.result()


def perform_azure_ocr(filepath, model_id="prebuilt-read", max_retries=3):
    """
    Fast, complete OCR for multi-page PDFs using a premium Azure Document Intelligence tier.
    Analyzes the entire document in a single API call without chunking.

    Strategy:
      1. Get an Azure client.
      2. Verify the document is a readable PDF with pages.
      3. Send the entire file to Azure for analysis in a single request.
      4. Implement a retry loop for transient API/network errors.
      5. Process the result and return the full extracted text.
    """
    client = get_azure_client()
    if not client:
        raise ConnectionError("Azure client not initialized. Check your config.")

    last_exception = None
    for attempt in range(max_retries):
        try:
            # The entire logic is now reduced to this single call.
            # _azure_analyze_file handles opening the file and sending the stream.
            result = _azure_analyze_file(client, model_id, filepath)

            # Process the successful result from the single API call
            full_text = []
            for page in result.pages:
                full_text.append(f"--- Page {page.page_number} ---")
                for line in page.lines:
                    full_text.append(line.content)
                full_text.append("")  # Adds a blank line for readability

            return "\n".join(full_text)

        except (HttpResponseError, ServiceResponseError, ServiceRequestError) as e:
            last_exception = e
            current_app.logger.warning(
                f"[Azure OCR] Retriable API error on attempt {attempt + 1}/{max_retries}. Error: {e}"
            )
            # Optional: time.sleep(2**attempt) for exponential backoff
        except Exception as e:
            # For non-retriable errors (e.g., bad file format), fail immediately
            current_app.logger.error(
                f"[Azure OCR] Unexpected, non-retriable error during analysis: {e}"
            )
            raise ConnectionError(
                f"An unexpected error occurred during Azure analysis: {e}"
            )

    # This part is reached only if all retries fail
    current_app.logger.error(
        f"[Azure OCR] All {max_retries} attempts failed. Last error: {last_exception}"
    )
    raise ConnectionError(
        f"Azure analysis failed after {max_retries} attempts: {last_exception}"
    )


# ---------------------------------------------------------------------
# (Optional) Legacy util — not used by new Azure path but kept for ref
# ---------------------------------------------------------------------


def split_pdf_to_pages(filepath):
    """Splits a multi-page PDF into single-page PDFs and returns their paths."""
    reader = PdfReader(filepath)
    temp_dir = tempfile.mkdtemp(prefix="single_pages_")
    filepaths = []
    for i in range(len(reader.pages)):
        writer = PdfWriter()
        writer.add_page(reader.pages[i])
        output_path = os.path.join(temp_dir, f"page_{i+1}.pdf")
        with open(output_path, "wb") as out:
            writer.write(out)
        filepaths.append(output_path)
    return filepaths


# ---------------------------------------------------------------------
# OpenAI classification / extraction
# ---------------------------------------------------------------------


def flatten_document_types(data):
    """Flattens the nested document type JSON."""
    flat_list = []
    if isinstance(data, dict):
        for value in data.values():
            flat_list.extend(flatten_document_types(value))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                flat_list.append(item)
            else:
                flat_list.extend(flatten_document_types(item))
    return flat_list


def analyze_document_with_openai(ocr_text, doc_types_path="document_types.json"):
    """Uses OpenAI GPT-4o to analyze OCR text; outputs JSON."""
    openai.api_key = current_app.config.get("OPENAI_API_KEY")
    if not openai.api_key:
        raise ConnectionError("OpenAI API key not configured.")

    try:
        with open(doc_types_path, "r") as f:
            nested_doc_types = json.load(f)
        doc_types = flatten_document_types(nested_doc_types)
    except FileNotFoundError:
        current_app.logger.error("document_types.json not found.")
        doc_types = ["Other"]
    except json.JSONDecodeError:
        current_app.logger.error("Invalid JSON in document_types.json.")
        doc_types = ["Other"]

    prompt = f"""
    You are an expert document analysis AI. Based on the OCR text provided, perform the tasks:
    1. Classify the document from this list: {json.dumps(doc_types)}. Use 'Other' if it doesn't match.
    2. Extract all Data from the pages.

    OCR Text:
    ---
    {ocr_text}
    ---

    Provide all the data from all pages
    """

    try:
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": "You are a document processing assistant designed to output JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        raise ConnectionError(f"OpenAI API call failed: {e}")

# ---------------------------------------------------------------------
# Counter functions for Dashboards
# ---------------------------------------------------------------------

# 1.⁠ ⁠total documents uploaded + 
# 2.⁠ ⁠Total characters/tokens extracted
# 3.⁠ ⁠Total space used
# 4.⁠ ⁠Total users + 
# 5.⁠ ⁠Total Token extracted from azure
# 6.⁠ ⁠Total Token extracted from tesseract
# 7.⁠ ⁠Total pages scanned + 
# 8.⁠ ⁠Total pages scanned by azure +
# 9.⁠ ⁠Total pages scanned by tesseract +
# total admin +
# total subadmin  +
# total categories  + 
# total subCategories  +
# total tags +

def format_bytes(size):
    """Converts bytes to a human-readable format (KB, MB, GB)."""
    if size is None:
        return "N/A"
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size >= power and n < len(power_labels) -1 :
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

# def get_s3_bucket_size():
#     """Fetches the total bucket size from AWS CloudWatch."""
#     try:
#         cloudwatch = boto3.client(
#             "cloudwatch",
#             aws_access_key_id=current_app.config.get("AWS_ACCESS_KEY"),
#             aws_secret_access_key=current_app.config.get("AWS_SECRET_KEY"),
#             region_name=current_app.config.get("AWS_REGION"),
#         )
#         bucket_name = current_app.config.get("AWS_S3_BUCKET")
        
#         # Get the latest data point from the last 48 hours
#         response = cloudwatch.get_metric_statistics(
#             Namespace='AWS/S3',
#             MetricName='BucketSizeBytes',
#             Dimensions=[
#                 {'Name': 'BucketName', 'Value': bucket_name},
#                 {'Name': 'StorageType', 'Value': 'StandardStorage'}
#             ],
#             StartTime=datetime.utcnow() - timedelta(days=2),
#             EndTime=datetime.utcnow(),
#             Period=86400, # Daily
#             Statistics=['Average'],
#             Unit='Bytes'
#         )
        
#         if response['Datapoints']:
#             # Get the most recent data point
#             latest_datapoint = sorted(response['Datapoints'], key=lambda x: x['Timestamp'], reverse=True)[0]
#             size_in_bytes = latest_datapoint['Average']
#             return format_bytes(size_in_bytes)
#         else:
#             return "0 B" # No data yet
#     except Exception as e:
#         current_app.logger.error(f"Could not get S3 bucket size from CloudWatch: {e}")
#         return "Error"

def get_s3_bucket_size():
    """
    Calculates the total bucket size by iterating through all objects in real-time.
    WARNING: This can be VERY SLOW for buckets with many files.
    """
    try:
        s3 = get_s3_client()
        bucket_name = current_app.config.get("AWS_S3_BUCKET")
        total_size = 0

        # S3 lists objects in "pages" of 1000. We must loop through all pages.
        # A paginator handles this looping for us automatically.
        paginator = s3.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name)

        for page in pages:
            # The 'Contents' key might not exist if a page is empty or the bucket is empty
            for obj in page.get('Contents', []):
                total_size += obj['Size']
        
        # We can reuse our existing helper to make the number readable
        return format_bytes(total_size)
    
    except Exception as e:
        current_app.logger.error(f"Could not get S3 bucket size by iterating: {e}")
        return "Error"


def get_dashboard_stats():
    """Fetches various statistics for the dashboard from the database."""
    stats = {
        'upload': 0,
        'admin': 0,
        'subadmin': 0,
        'categories': 0,
        'subcategories': 0,
        'tags': 0,
        'tesseract_count': 0,
        'azure_count': 0,
        'total_tokens': 0, 
        'tesseract_tokens': 0, 
        'azure_tokens': 0 ,
        's3_size': '0 B'
    }
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS count FROM documents")
            stats['upload'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM admin")
            stats['admin'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM subadmin")
            stats['subadmin'] = cursor.fetchone()['count'] # CORRECTED KEY

            cursor.execute("SELECT COUNT(*) AS count FROM categories")
            stats['categories'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM sub_categories")
            stats['subcategories'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM tags")
            stats['tags'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM documents WHERE ocr_engine = 'tesseract'")
            stats['tesseract_count'] = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM documents WHERE ocr_engine = 'azure'")
            stats['azure_count'] = cursor.fetchone()['count']

            cursor.execute("SELECT SUM(IFNULL(token_count, 0)) AS count FROM documents")
            stats['total_tokens'] = cursor.fetchone()['count'] or 0

            cursor.execute("SELECT SUM(IFNULL(token_count, 0)) AS count FROM documents WHERE ocr_engine = 'tesseract'")
            stats['tesseract_tokens'] = cursor.fetchone()['count'] or 0

            cursor.execute("SELECT SUM(IFNULL(token_count, 0)) AS count FROM documents WHERE ocr_engine = 'azure'")
            stats['azure_tokens'] = cursor.fetchone()['count'] or 0

    except Exception as e:
        current_app.logger.error(f"Error fetching dashboard stats: {e}")
        # Returns the dictionary of zeros in case of an error
    finally:
        if connection:
            connection.close()
    stats['s3_size'] = get_s3_bucket_size()

    return stats






#For searching / now cloed for new searching without page reload

# def is_document_relevant_openai(user_query, document_json):
#     """
#     Asks OpenAI if a document's extracted data is relevant to a user's query.
#     Returns True if relevant, False otherwise.
#     """
#     openai.api_key = current_app.config.get("OPENAI_API_KEY")
#     if not openai.api_key:
#         current_app.logger.error("OpenAI API key not configured for AI search.")
#         return False

#     # To save tokens and time, we just use the raw text content for the check.
#     # We can reconstruct a simplified text version from the JSON.
#     try:
#         data = json.loads(document_json)
#         # Attempt to find the most content-rich part of the JSON.
#         # This part might need adjustment based on your exact JSON structure.
#         document_text = json.dumps(data.get("extracted_data", data))
#     except (json.JSONDecodeError, TypeError):
#         # If it's not valid JSON or not a string, use it as is.
#         document_text = str(document_json)


#     # Truncate document text to avoid exceeding token limits and reduce costs.
#     # 12000 chars is ~3000 tokens, a safe limit for a quick check.
#     max_chars = 12000
#     if len(document_text) > max_chars:
#         document_text = document_text[:max_chars] + "..."

#     prompt = f"""
#     You are an intelligent document analysis assistant. Your task is to determine if the provided document text contains information that directly answers or relates to the user's query.

#     User's Query: "{user_query}"

#     Document's Extracted Data (in JSON format):
#     ---
#     {document_text}
#     ---

#     Based ONLY on the document's data provided, does it contain a relevant answer to the user's query?
#     For example, if the query is "customer name is John", the document must contain "John".
#     If the query is "find invoices over 5000", the document must contain an invoice with an amount over 5000.

#     Respond with a single word and nothing else: 'Yes' or 'No'.
#     """

#     try:
#         response = openai.chat.completions.create(
#             model="gpt-4o",  # Using a powerful model for better accuracy
#             messages=[
#                 {"role": "system", "content": "You are a document analysis assistant that responds with only 'Yes' or 'No'."},
#                 {"role": "user", "content": prompt}
#             ],
#             max_tokens=5,    # We only need a single word response
#             temperature=0.0  # We want a deterministic, factual answer
#         )
#         answer = response.choices[0].message.content.strip().lower()
#         # Check if 'yes' is in the answer for robustness
#         return 'yes' in answer
#     except Exception as e:
#         current_app.logger.error(f"OpenAI API call failed during AI search: {e}")
#         return False

# ---------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------
def sup_adm_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "sup_adm_id" not in session:
            flash("You need to log in first.", "warning")
            return redirect(url_for("main.admLogin", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def load_subadmin_permissions():
    """Load subadmin permissions into session"""
    if "subadmin_id" in session and "role_id" in session:
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "SELECT permissions FROM subadminroles WHERE r_id = %s",
                    (session["role_id"],),
                )
                role_data = cursor.fetchone()
                
                if role_data and role_data["permissions"]:
                    try:
                        permissions = json.loads(role_data["permissions"])
                        session["permissions"] = permissions
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error: {e}")
                        session["permissions"] = {}
                else:
                    session["permissions"] = {}
        except Exception as e:
            current_app.logger.error(f"Error loading permissions: {e}")
            session["permissions"] = {}
        finally:
            connection.close()
    else:
        print("Cannot load permissions: subadmin_id or role_id not in session")


def adm_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session and "subadmin_id" not in session:
            flash("You need to log in first.", "warning")
            return redirect(url_for("main.admLogin", next=request.url))

        # Load permissions for subadmin if not already loaded
        if "subadmin_id" in session and "permissions" not in session:
            load_subadmin_permissions()

        return f(*args, **kwargs)

    return decorated_function


def subadmin_permission_required(permission_key):
    """
    Decorator to check if subadmin has specific permission.
    permission_key format: "MODULE.ACTION" (e.g., "CATEGORIES.create_category")
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # If user is admin (not subadmin), allow access
            if "admin_id" in session:
                return f(*args, **kwargs)

            # If user is subadmin, check permissions from session
            if "subadmin_id" in session:
                # Ensure permissions are loaded
                if "permissions" not in session:
                    load_subadmin_permissions()

                # Check if permissions exist in session
                if "permissions" in session and session["permissions"]:
                    try:
                        # Split permission key into module and action
                        module, action = permission_key.split(".")

                        # Check if permission exists and is set to "Yes"
                        if (
                            module in session["permissions"]
                            and action in session["permissions"][module]
                            and session["permissions"][module][action] == "Yes"
                        ):
                            return f(*args, **kwargs)
                    except (ValueError, KeyError, AttributeError) as e:
                        current_app.logger.error(
                            f"Permission check error for {permission_key}: {e}"
                        )

                # Permission denied - render access denied page
                return render_template("accessdenied.html"), 403

            # Not logged in as either admin or subadmin
            flash("You need to log in first.", "warning")
            return redirect(url_for("main.admLogin"))

        return decorated_function
    return decorator


@main.context_processor
def inject_permissions():
    """Make permissions available to all templates"""
    permissions = {}
    if "subadmin_id" in session and "permissions" in session:
        permissions = session.get("permissions", {})
    elif "admin_id" in session:
        # Admin users have full permissions
        permissions = {"admin": True}
    return dict(permissions=permissions)


# -------------------------------------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------------------------------------


@main.route("/")
def home():
    return render_template("landingPage.html")


# -------------------------------------------------------------------------------------------
#  Authentication Routes -> Super Admin Authentication
# -------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------
#  Authentication Routes -> Super Admin Authentication -> Super Admin Authentication Forms
# --------------------------------------------------------------------------------------------


class supAdmRegistrationForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters long."),
            Regexp(
                r"^(?=.*[A-Za-z])(?=.*\d).+$",
                message="Password must contain letters and numbers.",
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Register")

    def validate_email(self, email):
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM superadmin WHERE superadmin_email=%s", (email.data,))
                if cursor.fetchone():
                    raise ValidationError("Email already exist in super admin portal . Please choose another.")
                
                cursor.execute("SELECT * FROM admin WHERE admin_email=%s", (email.data,))
                if cursor.fetchone():
                    raise ValidationError("Email already exist in admin portal. Please choose another.")
        finally:
            connection.close()


class supAdmLoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class admRegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters long."),
            Regexp(
                r"^(?=.*[A-Za-z])(?=.*\d).+$",
                message="Password must contain letters and numbers.",
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Register")

    def validate_email(self, email):
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:

                cursor.execute("SELECT * FROM superadmin WHERE superadmin_email=%s", (email.data,))
                if cursor.fetchone():
                    raise ValidationError("Email already exist in super admin portal . Please choose another.")
                
                cursor.execute("SELECT * FROM admin WHERE admin_email=%s", (email.data,))
                if cursor.fetchone():
                    raise ValidationError("Email already exist in admin portal. Please choose another.")
        finally:
            connection.close()


# ---------------------------------------------------------------------
# Authentication Routes -> Super Admin Authentication -> Routes
# ---------------------------------------------------------------------


@main.route("/superadmin/supadmregistration", methods=["GET", "POST"])
def supAdmRegistration():
    if does_superadmin_exist():
        flash("Registration is disabled. Only one superadmin account is allowed.", "warning")
        return redirect(url_for("main.admLogin")) # Redirect to the main login
    
    form = supAdmRegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(
            form.password.data.encode("utf-8"), bcrypt.gensalt()
        )
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO superadmin (superadmin_name, superadmin_email, superadmin_password) VALUES (%s, %s, %s)",
                    (form.name.data, form.email.data, hashed_password)
                )
                connection.commit()
                
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("main.admLogin"))
            
        except Exception as e:
            connection.rollback()
            flash(f"Error during registration: {str(e)}", "danger")
        finally:
            connection.close()
    
    return render_template("supAdmRegistration.html", form=form)

# @main.route("/superadmin/supadmlogin", methods=["GET", "POST"])
# def supAdmlogin():
#     form = supAdmLoginForm()
#     if form.validate_on_submit():
#         connection = get_db_connection()
#         try:
#             with connection.cursor() as cursor:
#                 cursor.execute(
#                     "SELECT * FROM superadmin WHERE superadmin_email=%s", (form.email.data,)
#                 )
#                 user = cursor.fetchone()
                
#             if user and bcrypt.checkpw(
#                 form.password.data.encode("utf-8"), user['superadmin_password'].encode("utf-8")
#             ):
#                 session["sup_adm_id"] = user['superadmin_id']
#                 session["sup_adm_name"] = user['superadmin_name']
#                 session["sup_adm_mail"] = user['superadmin_email']
                
#                 log_user_activity(
#                     user['superadmin_id'],
#                     user['superadmin_name'],
#                     "Super Admin",
#                     "Login",
#                     "Landing Page/Login",
#                     f"Super Admin logged in, Id: {user['superadmin_id']}"
#                 )
                
#                 return redirect(url_for("main.supAdmDashboard"))
#             else:
#                 flash("Login failed. Please check your email and password.", "error")
                
#         except Exception as e:
#             flash(f"Error during login: {str(e)}", "danger")
#         finally:
#             connection.close()
            
#     return render_template("supAdmLogin.html", form=form)


@main.route("/superadmin/supadmdashboard")
@sup_adm_login_required
def supAdmDashboard():
    return render_template("supAdmDashboard.html")


@main.route("/superadmin/supadmlogout")
@sup_adm_login_required
def supAdmLogout():
    try:
        log_user_activity(
            session["sup_adm_id"],
            session.get("sup_adm_name", "Unknown"),
            "Super Admin",
            "Logout",
            "Landing Page/Logout",
            f"Super Admin Logged out, Id : {session['sup_adm_id']}",
        )
    except Exception as e:
        current_app.logger.error(f"Error logging out superadmin: {e}")
    
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("main.admLogin"))


@main.route("/superadmin/supadmprofile", methods=["GET", "POST"])
@sup_adm_login_required
def supAdmProfile():
    connection = get_db_connection()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM superadmin WHERE superadmin_id = %s", (session["sup_adm_id"],)
            )
            superadmin = cursor.fetchone()
            print(f"Fetched user: {superadmin}")
            return render_template("supAdmProfile.html", superadmin=superadmin)
    except Exception as e:
        current_app.logger.error(f"Error fetching superadmin profile: {e}")
        flash("An error occurred while fetching your profile.", "danger")
        return redirect(url_for("main.supAdmlogin"))
    finally:
        connection.close()


@main.route("/superadmin/supadmcreateadmin", methods=["GET", "POST"])
@sup_adm_login_required
def supAdmCreateAdmin():
    form = admRegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(
            form.password.data.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "INSERT INTO admin (admin_name, admin_email, admin_password, superadmin_id) VALUES (%s, %s, %s, %s)",
                    (
                        form.name.data,
                        form.email.data,
                        hashed_password,
                        session["sup_adm_id"],
                    ),
                )
                connection.commit()
                flash("New Admin Created successfully", "success")

                cursor.execute(
                    "SELECT * FROM admin WHERE admin_email = %s", (form.email.data,)
                )
                admin = cursor.fetchone()
                log_user_activity(
                    session["sup_adm_id"],
                    session.get("sup_adm_name", "Unknown"),
                    "Super Admin",
                    "Add",
                    "App/Admin Portal/Creat Admin",
                    f"Created New Admin Name : {admin['admin_name']} with admin id :{admin['admin_id']} by Super Admin ({session['sup_adm_name']}), Id : {session['sup_adm_id']}",
                )
        except Exception as e:
            connection.rollback()
            flash(f"Error creating admin: {e}", "danger")
        finally:
            connection.close()

    connection = get_db_connection()
    adminlist = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            query = """
                SELECT a.admin_id, a.admin_name, a.admin_email, a.created_at, s.superadmin_id, s.superadmin_name
                FROM admin AS a
                INNER JOIN superadmin AS s ON a.superadmin_id = s.superadmin_id
                ORDER BY a.admin_id ASC
            """
            cursor.execute(query)
            adminlist = cursor.fetchall()
    except Exception as e:
        current_app.logger.error(f"Error fetching admin list: {e}")
        flash("An error occurred while fetching admin list.", "danger")
    finally:
        connection.close()
    
    return render_template("supAdmAdmin.html", form=form, adminlist=adminlist)


#
# PASTE THIS ENTIRE CORRECTED FUNCTION IN app/routes.py
#

@main.route("/superadmin/supadmactivities")
@sup_adm_login_required
def supAdmActivities():
    page = request.args.get("page", 1, type=int)
    per_page = 20
    event_type = request.args.get("event_type")
    admin_filter = request.args.get("admin")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    
    connection = get_db_connection()
    activities = []
    total = 0
    event_types = []

    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            # --- CORRECTION 1: Query the correct table and filter for Super Admin ---
            query = "SELECT * FROM user_activities WHERE user_type = 'Super Admin'"
            
            conditions = []
            params = []
            
            if event_type:
                conditions.append("event_type = %s")
                params.append(event_type)
            
            if admin_filter:
                # --- CORRECTION 2: Use the correct column name 'user_name' ---
                conditions.append("user_name LIKE %s")
                params.append(f"%{admin_filter}%")
            
            if date_from:
                conditions.append("event_time >= %s")
                params.append(date_from)
            
            if date_to:
                conditions.append("event_time <= %s")
                params.append(f"{date_to} 23:59:59")

            # The 'WHERE' is already in the base query, so we start with 'AND'
            if conditions:
                query += " AND " + " AND ".join(conditions)

            # Use a slightly different approach for count_query to be safe
            count_query = f"SELECT COUNT(*) as total FROM ({query}) as filtered"
            
            # We pass the full params list to the count query
            cursor.execute(count_query, tuple(params))
            total_result = cursor.fetchone()
            total = total_result['total'] if total_result else 0


            query += " ORDER BY id DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            cursor.execute(query, tuple(params))
            activities = cursor.fetchall()

            # --- CORRECTION 3: Get distinct event types from the correct table ---
            cursor.execute(
                "SELECT DISTINCT event_type FROM user_activities WHERE user_type = 'Super Admin' ORDER BY event_type"
            )
            event_types = [row["event_type"] for row in cursor.fetchall()]

    except Exception as e:
        current_app.logger.error(f"Error fetching superadmin activities: {e}")
        flash("An error occurred while fetching activities.", "danger")
    finally:
        connection.close()

    total_pages = (total + per_page - 1) // per_page if total > 0 else 0
    page_items, last_page = [], 0
    for page_num in range(1, total_pages + 1):
        if page_num <= 2 or page_num > total_pages - 2 or abs(page_num - page) <= 2:
            if last_page + 1 != page_num:
                page_items.append(None)
            page_items.append(page_num)
            last_page = page_num
    
    pagination = {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_num": page - 1,
        "next_num": page + 1,
        "iter_pages": lambda: page_items,
    }

    return render_template(
        "supAdmActivities.html",
        activities=activities,
        pagination=pagination,
        event_types=event_types,
        current_filters={
            "event_type": event_type,
            "admin": admin_filter,
            "date_from": date_from,
            "date_to": date_to,
        },
    )
# ---------------------------------------------------------------------
# Authentication Routes -> Admin Authentication -> Routes
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

@main.route("/admin/admlogin", methods=["GET", "POST"])
def admLogin():
    form = LoginForm()
    if form.validate_on_submit():
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                # checking if it's an super admin
                cursor.execute("SELECT * FROM superadmin WHERE superadmin_email=%s", (form.email.data,))
                superadmin = cursor.fetchone()

                if superadmin:
                  if superadmin and bcrypt.checkpw(
                   form.password.data.encode("utf-8"), superadmin['superadmin_password'].encode("utf-8") ):
                    session["sup_adm_id"] = superadmin['superadmin_id']
                    session["sup_adm_name"] = superadmin['superadmin_name']
                    session["sup_adm_mail"] = superadmin['superadmin_email']
                
                    log_user_activity(
                      superadmin['superadmin_id'],
                      superadmin['superadmin_name'],
                      "Super Admin",
                      "Login",
                      "Landing Page/Login",
                      f"Super Admin logged in, Id: {superadmin['superadmin_id']}"
                   )
                
                  return redirect(url_for("main.supAdmDashboard"))


                # checking if it's an admin
                cursor.execute("SELECT * FROM admin WHERE admin_email=%s", (form.email.data,))
                user = cursor.fetchone()

                if user:
                    if bcrypt.checkpw(form.password.data.encode("utf-8"), user["admin_password"].encode("utf-8")):
                        session["admin_id"] = user["admin_id"]
                        session["admin_name"] = user["admin_name"]
                        session["admin_mail"] = user["admin_email"]
                        session["user_type"] = "admin"
                        log_user_activity(
                            user["admin_id"],
                            user["admin_name"],
                            "Admin",
                            "Login",
                            "Landing Page/Login",
                            f"Admin logged in, Id: {user['admin_id']}, Name: {user['admin_name']}, Email: {user['admin_email']}",
                        )
                        return redirect(url_for("main.admDashboard"))
                
                # If not an admin, checking if it's a subadmin
                cursor.execute(
                    "SELECT * FROM subadmin WHERE subadmin_email=%s", (form.email.data,)
                )
                subadmin_user = cursor.fetchone()

                if subadmin_user:
                    password_hash = subadmin_user.get("subadmin_password")
                    if password_hash and bcrypt.checkpw(form.password.data.encode("utf-8"), password_hash.encode("utf-8")):
                        session["subadmin_id"] = subadmin_user["subadmin_id"]
                        session["subadmin_name"] = subadmin_user["subadmin_name"]
                        session["subadmin_email"] = subadmin_user["subadmin_email"]
                        session["subadmin_username"] = subadmin_user["subadmin_username"]
                        session["role_id"] = subadmin_user["role_id"]
                        session["user_type"] = "subadmin"
                        load_subadmin_permissions()
                        log_user_activity(
                            subadmin_user["subadmin_id"],
                            subadmin_user["subadmin_name"],
                            "Subadmin",
                            "Login",
                            "Landing Page/Login",
                            f"Subadmin logged in, Id: {subadmin_user['subadmin_id']}, Name: {subadmin_user['subadmin_name']}",
                        )
                        return redirect(url_for("main.admDashboard"))
        
        except Exception as e:
            current_app.logger.error(f"Error during login: {e}")
            flash(f"Error during login: {str(e)}", "danger")
        finally:
            connection.close()

        flash("Login failed. Please check your email and password.", "error")
        return redirect(url_for("main.admLogin"))
    
    return render_template("admLogin.html", form=form)



@main.route("/admin/admdashboard")
@adm_login_required
@subadmin_permission_required("DASHBOARDS.view_dashboard")
def admDashboard():

    dashboard_stats = get_dashboard_stats()

    return render_template("admDashboard.html", stats=dashboard_stats)



@main.route("/admin/admlogout")
@adm_login_required
def admLogout():
    try:
        user_id = session.get("admin_id") or session.get("subadmin_id")
        user_name = session.get("admin_name") or session.get("subadmin_name")
        user_type = session.get("user_type")
        
        log_user_activity(
            user_id,
            user_name,
            user_type,
            "Logout",
            "Landing Page/Logout",
            f"{user_type} logged out, Id: {user_id}, Name: {user_name}",
        )
    except Exception as e:
        current_app.logger.error(f"Error logging out admin/subadmin: {e}")

    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("main.admLogin"))

@main.route("/admin/admprofile")
@adm_login_required
def admProfile():
    connection = get_db_connection()
    user = None
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            if "admin_id" in session:
                cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (session["admin_id"],))
            elif "subadmin_id" in session:
                cursor.execute("SELECT * FROM subadmin WHERE subadmin_id = %s", (session["subadmin_id"],))
            
            user = cursor.fetchone()
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for("main.admLogin"))
            
            return render_template("admProfile.html", user=user, user_type=session.get("user_type"))
    except Exception as e:
        current_app.logger.error(f"Error fetching admin/subadmin profile: {e}")
        flash("An error occurred while fetching your profile.", "danger")
        return redirect(url_for("main.admLogin"))
    finally:
        connection.close()

# # ---------------------------------------------------------------------
# # Master: Categories
# # ---------------------------------------------------------------------

@main.route("/master/categories")
@adm_login_required
@subadmin_permission_required("CATEGORIES.view_categories")
def categories():
    connection = get_db_connection()
    all_categories = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT c_id , category_name, DATE_FORMAT(c_created_at, '%d-%m-%Y %r') as c_created_at FROM categories ORDER BY c_id ASC"
            )
            all_categories = cursor.fetchall()
    except Exception as e:
        current_app.logger.error(f"Error fetching categories: {e}")
        flash("An error occurred while fetching categories.", "danger")
    finally:
        connection.close()
    return render_template("categories.html", categories=all_categories)


@main.route("/master/categories/add", methods=["POST"])
@adm_login_required
@subadmin_permission_required("CATEGORIES.create_category")
def add_category():
    category_name = request.form.get("categoryName")
    if not category_name:
        flash("Category name cannot be empty.", "danger")
        return redirect(url_for("main.categories"))
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO categories (category_name) VALUES (%s)", (category_name,)
            )
        connection.commit()

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            'Create',
            'App/Master Entries/Categories',
            f"Created New Category Called '{category_name}'"
        )
        
        flash("Category added successfully!", "success")
    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("Another category with this name already exists.", "danger")
    except Exception as e:
        connection.rollback()
        flash(f"An error occurred: {e}", "danger")
    finally:
        connection.close()
    return redirect(url_for("main.categories"))


@main.route("/master/categories/edit/<int:cat_id>", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("CATEGORIES.edit_category")
def edit_category(cat_id):
    connection = get_db_connection()
    try:
        if request.method == "POST":
            new_name = request.form.get("categoryName")
            if not new_name:
                flash("Category name cannot be empty.", "danger")
                return redirect(url_for("main.categories"))
            
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE categories SET category_name = %s WHERE c_id = %s",
                    (new_name, cat_id),
                )
            connection.commit()
            
            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                'Edit',
                'App/Master Entries/Categories',
                f"Edited Category '{new_name}' with Category ID = '{cat_id}'"
            )
            
            flash("Category updated successfully!", "success")
        else:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "SELECT c_id, category_name FROM categories WHERE c_id = %s", (cat_id,)
                )
                category = cursor.fetchone()
                if not category:
                    flash("Category not found.", "danger")
                    return redirect(url_for("main.categories"))
    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("Another category with this name already exists.", "danger")
    except Exception as e:
        connection.rollback()
        flash(f"An error occurred: {e}", "danger")
    finally:
        connection.close()
    return redirect(url_for("main.categories"))


@main.route("/master/categories/delete/<int:cate_id>", methods=["POST"])
@adm_login_required
@subadmin_permission_required("CATEGORIES.delete_category")
def delete_category(cate_id):
    if request.method == "POST":
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                # for "log_user_activity"
                cursor.execute(
                    "SELECT category_name FROM categories WHERE c_id = %s", (cate_id,)
                )
                category = cursor.fetchone()

                cursor.execute("DELETE FROM categories WHERE c_id = %s", (cate_id,))
            connection.commit()

            if category:
                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    'Delete',
                    'App/Master Entries/Categories',
                    f"Deleted Category '{category['category_name']}' with Category ID '{cate_id}'"
                )
            
            flash("Category and all its sub-categories have been deleted.", "success")
        except Exception as e:
            connection.rollback()
            flash(f"An error occurred: {e}", "danger")
        finally:
            connection.close()
    return redirect(url_for("main.categories"))

# # ---------------------------------------------------------------------
# # Master: Sub-Categories
# # ---------------------------------------------------------------------


@main.route("/master/sub-categories")
@adm_login_required
@subadmin_permission_required("SUB_CATEGORIES.view_sub_categories")
def subCategories():
    connection = get_db_connection()
    all_categories = []
    all_subcategories = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT c_id , category_name FROM categories ORDER BY c_id ASC")
            all_categories = cursor.fetchall()
            
            sub_sql_com = """
                SELECT
                    sc.sc_id,
                    c.category_name AS category_name,
                    sc.sub_category_name,
                    DATE_FORMAT(sc.sc_created_at, '%d-%m-%Y %r') AS sc_created_at
                FROM  
                    sub_categories sc
                INNER JOIN  
                    categories c ON sc.category_id = c.c_id
                ORDER BY  
                    sc.sc_id ASC  
            """
            cursor.execute(sub_sql_com)
            all_subcategories = cursor.fetchall()
    except Exception as e:
        current_app.logger.error(f"Error fetching sub-categories: {e}")
        flash("An error occurred while fetching sub-categories.", "danger")
    finally:
        connection.close()
    return render_template(
        "subCategories.html",
        all_categories=all_categories,
        all_subcategories=all_subcategories,
    )


@main.route("/master/sub-categories/add", methods=["POST"])
@adm_login_required
@subadmin_permission_required("SUB_CATEGORIES.create_sub_category")
def add_sub_category():
    category_id = request.form.get("category_id")
    sub_category_name = request.form.get("sub_category_name")

    if not category_id or not sub_category_name:
        flash("Both category and sub-category name are required.", "danger")
        return redirect(url_for("main.subCategories"))
    
    connection = get_db_connection()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT category_name FROM categories WHERE c_id = %s", (category_id,)
            )
            category_data = cursor.fetchone()
            category_name = category_data["category_name"] if category_data else "Unknown"
            
            cursor.execute(
                "INSERT INTO sub_categories (category_id, sub_category_name) VALUES (%s, %s)",
                (category_id, sub_category_name),
            )
        connection.commit()

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            'Create',
            'App/Master Entries/Sub Categories',
            f"Created New Sub Category Called '{sub_category_name}' with Category name '{category_name}' Category ID '{category_id}'"
        )

        flash("Sub-category added successfully!", "success")
    except ValueError:
        connection.rollback()
        flash("Invalid category ID.", "danger")
    except pymysql.err.IntegrityError as e:
        connection.rollback()
        if "Duplicate entry" in str(e):
            flash(
                "A sub-category with this name already exists under the selected category.",
                "danger",
            )
        else:
            flash(f"A database error occurred: {e}", "danger")
    except Exception as e:
        connection.rollback()
        flash(f"An error occurred: {e}", "danger")
    finally:
        connection.close()
    return redirect(url_for("main.subCategories"))


@main.route("/master/sub-categories/edit/<int:sub_cat_id>", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("SUB_CATEGORIES.edit_sub_category")
def edit_sub_category(sub_cat_id):
    connection = get_db_connection()
    try:
        if request.method == "POST":
            new_name = request.form.get("subCategoryName")
            if not new_name:
                flash("Sub Category name cannot be empty.", "danger")
                return redirect(url_for("main.subCategories"))
            
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "SELECT sub_category_name FROM sub_categories WHERE sc_id = %s", (sub_cat_id,)
                )
                old_sub_cat = cursor.fetchone()

                cursor.execute(
                    "UPDATE sub_categories SET sub_category_name = %s WHERE sc_id = %s",
                    (new_name, sub_cat_id),
                )
            connection.commit()

            if old_sub_cat:
                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    'Edit',
                    'App/Master Entries/Sub Categories',
                    f"Edited Sub category from '{old_sub_cat['sub_category_name']}' to '{new_name}' with Sub Category ID = '{sub_cat_id}'"
                )

            flash("Sub Category updated successfully!", "success")
    
    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("Another Sub Category with this name already exists.", "danger")
    except Exception as e:
        connection.rollback()
        flash(f"An error occurred: {e}", "danger")
    finally:
        connection.close()
    return redirect(url_for("main.subCategories"))


@main.route("/master/sub-categories/delete/<int:sub_cat_id>", methods=["POST"])
@adm_login_required
@subadmin_permission_required("SUB_CATEGORIES.delete_sub_category")
def delete_sub_category(sub_cat_id):
    if request.method == "POST":
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                # for "log_user_activity"
                cursor.execute(
                    "SELECT sub_category_name FROM sub_categories WHERE sc_id = %s",
                    (sub_cat_id,),
                )
                sub_category = cursor.fetchone()

                cursor.execute("DELETE FROM sub_categories WHERE sc_id = %s", (sub_cat_id,))
            connection.commit()

            if sub_category:
                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    'Delete',
                    'App/Master Entries/Sub Categories',
                    f"Deleted Sub Category '{sub_category['sub_category_name']}' with Sub Category ID '{sub_cat_id}'"
                )

            flash("Sub Categories have been deleted.", "success")
        except Exception as e:
            connection.rollback()
            flash(f"An error occurred: {e}", "danger")
        finally:
            connection.close()
    return redirect(url_for("main.subCategories"))

# # ---------------------------------------------------------------------
# # Master: Tags
# # ---------------------------------------------------------------------


@main.route("/master/tags")
@adm_login_required
@subadmin_permission_required("TAGS.view_tags")
def tags():
    connection = get_db_connection()
    all_tags = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT t_id , tag_name, DATE_FORMAT(t_created_at, '%d-%m-%Y %r') as t_created_at FROM tags ORDER BY t_id ASC"
            )
            all_tags = cursor.fetchall()
    except Exception as e:
        current_app.logger.error(f"Error fetching tags: {e}")
        flash("An error occurred while fetching tags.", "danger")
    finally:
        connection.close()
    return render_template("tags.html", all_tags=all_tags)


@main.route("/master/tags/add", methods=["POST"])
@adm_login_required
@subadmin_permission_required("TAGS.create_tag")
def add_tag():
    tag_name = request.form.get("tagName")
    if not tag_name:
        flash("Tag name cannot be empty.", "danger")
        return redirect(url_for("main.tags"))
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO tags (tag_name) VALUES (%s)", (tag_name,))
        connection.commit()
        
        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            'Create',
            'App/Master Entries/Tags',
            f"Created New Tag Called '{tag_name}'"
        )
        
        flash("Tag added successfully!", "success")
    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("Another Tag with this name already exists.", "danger")
    except Exception as e:
        connection.rollback()
        flash(f"An error occurred: {e}", "danger")
    finally:
        connection.close()
    return redirect(url_for("main.tags"))


@main.route("/master/tags/edit/<int:tag_id>", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("TAGS.edit_tag")
def edit_tag(tag_id):
    connection = get_db_connection()
    try:
        if request.method == "POST":
            new_name = request.form.get("tagName")
            if not new_name:
                flash("Tag name cannot be empty.", "danger")
                return redirect(url_for("main.tags"))
            
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "SELECT tag_name FROM tags WHERE t_id = %s", (tag_id,)
                )
                old_tag = cursor.fetchone()

                cursor.execute(
                    "UPDATE tags SET tag_name = %s WHERE t_id = %s", (new_name, tag_id)
                )
            connection.commit()
            
            if old_tag:
                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    'Edit',
                    'App/Master Entries/Tags',
                    f"Edited Tag from '{old_tag['tag_name']}' to '{new_name}' where Tag ID = '{tag_id}'"
                )
            
            flash("Tag updated successfully!", "success")
        
    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("Another Tag with this name already exists.", "danger")
    except Exception as e:
        connection.rollback()
        flash(f"An error occurred: {e}", "danger")
    finally:
        connection.close()
    return redirect(url_for("main.tags"))


@main.route("/master/tags/delete/<int:tag_id>", methods=["POST"])
@adm_login_required
@subadmin_permission_required("TAGS.delete_tag")
def delete_tag(tag_id):
    if request.method == "POST":
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute("SELECT tag_name FROM tags WHERE t_id = %s", (tag_id,))
                tag = cursor.fetchone()

                cursor.execute("DELETE FROM tags WHERE t_id = %s", (tag_id,))
            connection.commit()

            if tag:
                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    'Delete',
                    'App/Master Entries/Tags',
                    f"Deleted Tag '{tag['tag_name']}' with Tag ID '{tag_id}'"
                )
            
            flash("Tag has been deleted.", "success")
        except Exception as e:
            connection.rollback()
            flash(f"An error occurred: {e}", "danger")
        finally:
            connection.close()
    return redirect(url_for("main.tags"))

# # ---------------------------------------------------------------------
# # Document Routes
# # ---------------------------------------------------------------------


# @main.route("/documents/add-new", methods=["GET", "POST"])
# @adm_login_required
# @subadmin_permission_required("DOCUMENTS.create_document")
# def addNewDocuments():
#     """
#     Handles the initial form submission for document analysis.
#     Performs OCR and AI analysis and returns the extracted data to the client.
#     """
#     if request.method == "POST":
#         if "file" not in request.files:
#             return jsonify({"error": "No file part in the request"}), 400
#         file = request.files["file"]
#         if file.filename == "":
#             return jsonify({"error": "No file selected"}), 400

#         form_data = request.form
#         title = form_data.get("title")
#         if not title:
#             return jsonify({"error": "Title is a required field."}), 400

#         filepath = None
#         try:
#             if file and allowed_file(file.filename):
#                 original_filename = secure_filename(file.filename)
#                 file_extension = os.path.splitext(original_filename)[1]
#                 unique_filename = f"{uuid.uuid4().hex}{file_extension}"
#                 filepath = os.path.join(
#                     current_app.config["UPLOAD_FOLDER"], unique_filename
#                 )
#                 file.save(filepath)

#                 # Store the filepath and original filename in the session for final submission
#                 session["processing_filepath"] = filepath
#                 session["processing_filename"] = original_filename
#                 session["form_data_for_submission"] = dict(form_data)

#                 ocr_engine = form_data.get("ocr_engine", "azure")

#                 session["form_data_for_submission"]['ocr_engine'] = ocr_engine

#                 raw_text = ""
#                 if ocr_engine == "tesseract":
#                     mime_type = magic.from_file(filepath, mime=True)
#                     raw_text = perform_tesseract_ocr(filepath, mime_type)
#                 else:
#                     raw_text = perform_azure_ocr(filepath)

#                 if not raw_text.strip():
#                     os.remove(filepath)
#                     session.pop("processing_filepath", None)
#                     return jsonify({"error": "OCR failed to extract any text from the document."}), 400
                
#                 token_count = len(raw_text.split())
#                 session['form_data_for_submission']['token_count'] = token_count

#                 log_user_activity(
#                     session.get("admin_id") or session.get("subadmin_id"),
#                     session.get("admin_name") or session.get("subadmin_name"),
#                     session.get("user_type"),
#                     "File Upload",
#                     "Documents/Add New",
#                     f"Uploaded document '{original_filename}' for analysis."
#                 )

#                 analysis_result = analyze_document_with_openai(raw_text)
#                 return jsonify(
#                     {
#                         "message": "Document analyzed successfully. Please review and save.",
#                         "extracted_data": analysis_result,
#                     }
#                 )
#             else:
#                 return jsonify({"error": "File type not allowed"}), 400
#         except ConnectionError as e:
#             if filepath and os.path.exists(filepath):
#                 os.remove(filepath)
#             return jsonify({"error": str(e)}), 500
#         except Exception as e:
#             if filepath and os.path.exists(filepath):
#                 os.remove(filepath)
#             current_app.logger.error(f"An unexpected error occurred: {e}")
#             return jsonify({"error": "An internal error occurred. Please try again later."}), 500

#     return render_template("addNewDocuments.html")



# @main.route("/documents/add-new", methods=["GET", "POST"])
# @adm_login_required
# @subadmin_permission_required("DOCUMENTS.create_document")
# def addNewDocuments():
#     """
#     Handles the initial form submission for document analysis.
#     Performs OCR and AI analysis and returns the extracted data to the client.
#     """
#     if request.method == "POST":
#         if "file" not in request.files:
#             return jsonify({"error": "No file part in the request"}), 400
#         file = request.files["file"]
#         if file.filename == "":
#             return jsonify({"error": "No file selected"}), 400

#         form_data = request.form
#         title = form_data.get("title")
#         if not title:
#             return jsonify({"error": "Title is a required field."}), 400

#         filepath = None
#         try:
#             if file and allowed_file(file.filename):
#                 original_filename = secure_filename(file.filename)
                
#                 # --- CHANGE: Generate a unique filename for storage ---
#                 file_extension = os.path.splitext(original_filename)[1]
#                 unique_filename = f"{uuid.uuid4().hex}{file_extension}"
                
#                 # Save the temp file with the unique name
#                 filepath = os.path.join(
#                     current_app.config["UPLOAD_FOLDER"], unique_filename
#                 )
#                 file.save(filepath)

#                 # --- CHANGE: Store BOTH filenames in the session for the next step ---
#                 session["processing_filepath"] = filepath
#                 session["original_filename"] = original_filename          # For displaying to user
#                 session["unique_filename_for_s3"] = unique_filename    # For saving to S3
#                 session["form_data_for_submission"] = dict(form_data)

#                 ocr_engine = form_data.get("ocr_engine", "azure")
#                 session["form_data_for_submission"]['ocr_engine'] = ocr_engine

#                 raw_text = ""
#                 if ocr_engine == "tesseract":
#                     mime_type = magic.from_file(filepath, mime=True)
#                     raw_text = perform_tesseract_ocr(filepath, mime_type)
#                 else:
#                     raw_text = perform_azure_ocr(filepath)

#                 if not raw_text.strip():
#                     os.remove(filepath)
#                     session.pop("processing_filepath", None)
#                     return jsonify({"error": "OCR failed to extract any text from the document."}), 400
                
#                 token_count = len(raw_text.split())
#                 session['form_data_for_submission']['token_count'] = token_count

#                 log_user_activity(
#                     session.get("admin_id") or session.get("subadmin_id"),
#                     session.get("admin_name") or session.get("subadmin_name"),
#                     session.get("user_type"),
#                     "File Upload",
#                     "Documents/Add New",
#                     f"Uploaded document '{original_filename}' for analysis."
#                 )

#                 analysis_result = analyze_document_with_openai(raw_text)
#                 return jsonify(
#                     {
#                         "message": "Document analyzed successfully. Please review and save.",
#                         "extracted_data": analysis_result,
#                     }
#                 )
#             else:
#                 return jsonify({"error": "File type not allowed"}), 400
#         except ConnectionError as e:
#             if filepath and os.path.exists(filepath):
#                 os.remove(filepath)
#             return jsonify({"error": str(e)}), 500
#         except Exception as e:
#             if filepath and os.path.exists(filepath):
#                 os.remove(filepath)
#             current_app.logger.error(f"An unexpected error occurred: {e}")
#             return jsonify({"error": "An internal error occurred. Please try again later."}), 500

#     return render_template("addNewDocuments.html")



@main.route("/documents/add-new", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("DOCUMENTS.create_document")
def addNewDocuments():
    """
    Handles the initial form submission for document analysis.
    Performs OCR and AI analysis and returns the extracted data to the client.
    """
    if request.method == "POST":
        # --- This POST logic remains unchanged ---
        if "file" not in request.files:
            return jsonify({"error": "No file part in the request"}), 400
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        form_data = request.form
        title = form_data.get("title")
        if not title:
            return jsonify({"error": "Title is a required field."}), 400

        filepath = None
        try:
            if file and allowed_file(file.filename):
                original_filename = secure_filename(file.filename)
                file_extension = os.path.splitext(original_filename)[1]
                unique_filename = f"{uuid.uuid4().hex}{file_extension}"
                filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_filename)
                file.save(filepath)

                session["processing_filepath"] = filepath
                session["original_filename"] = original_filename
                session["unique_filename_for_s3"] = unique_filename
                session["form_data_for_submission"] = dict(form_data)

                ocr_engine = form_data.get("ocr_engine", "azure")
                session["form_data_for_submission"]['ocr_engine'] = ocr_engine

                raw_text = ""
                if ocr_engine == "tesseract":
                    mime_type = magic.from_file(filepath, mime=True)
                    raw_text = perform_tesseract_ocr(filepath, mime_type)
                else:
                    raw_text = perform_azure_ocr(filepath)

                if not raw_text.strip():
                    os.remove(filepath)
                    session.pop("processing_filepath", None)
                    return jsonify({"error": "OCR failed to extract any text from the document."}), 400
                
                token_count = len(raw_text.split())
                session['form_data_for_submission']['token_count'] = token_count

                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    "File Upload",
                    "Documents/Add New",
                    f"Uploaded document '{original_filename}' for analysis."
                )

                analysis_result = analyze_document_with_openai(raw_text)
                return jsonify({
                    "message": "Document analyzed successfully. Please review and save.",
                    "extracted_data": analysis_result,
                })
            else:
                return jsonify({"error": "File type not allowed"}), 400
        except ConnectionError as e:
            if filepath and os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            if filepath and os.path.exists(filepath):
                os.remove(filepath)
            current_app.logger.error(f"An unexpected error occurred: {e}")
            return jsonify({"error": "An internal error occurred. Please try again later."}), 500

    # --- THIS GET LOGIC IS NEW ---
    # On initial page load (GET request), fetch all options for the dropdowns
    connection = get_db_connection()
    all_categories = []
    all_subcategories = []
    all_tags = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT category_name FROM categories ORDER BY category_name ASC")
            all_categories = cursor.fetchall()
            cursor.execute("SELECT sub_category_name FROM sub_categories ORDER BY sub_category_name ASC")
            all_subcategories = cursor.fetchall()
            cursor.execute("SELECT tag_name FROM tags ORDER BY tag_name ASC")
            all_tags = cursor.fetchall()
    except Exception as e:
        current_app.logger.error(f"Error fetching dropdown data for add new page: {e}")
        flash("Could not load dropdown options.", "danger")
    finally:
        if connection:
            connection.close()
    
    return render_template(
        "addNewDocuments.html", 
        categories=all_categories,
        subcategories=all_subcategories,
        tags=all_tags
    )




# @main.route("/documents/submit", methods=["POST"])
# @adm_login_required
# def submitDocument():
#     """
#     Handles the final submission after the user has reviewed and edited the extracted data.
#     """
#     filepath = session.get("processing_filepath")
#     form_data = session.get("form_data_for_submission")
#     original_filename = session.get("processing_filename")

#     if not filepath or not form_data:
#         return jsonify({"error": "Analysis data not found. Please re-analyze the document."}), 400

#     edited_data_json_str = request.form.get("extracted_data")
#     if not edited_data_json_str:
#         return jsonify({"error": "No extracted data provided for submission."}), 400

#     try:
#         json.loads(edited_data_json_str)
#     except json.JSONDecodeError:
#         return jsonify({"error": "Invalid JSON format in the extracted data."}), 400

#     connection = get_db_connection()
#     try:
#         file_url = None
#         # Use the file from the session's temporary path for S3 upload
#         with open(filepath, 'rb') as f:
#             # We need to create a temporary file-like object for boto3
#             # or pass the file stream with the correct filename.
#             # boto3's upload_fileobj needs a filename, so we'll simulate it.
#             f.name = original_filename
#             file_url = upload_file_to_s3(f, current_app.config.get("AWS_S3_BUCKET"))

#         if not file_url:
#             raise Exception("Failed to upload file to S3.")

#         with connection.cursor() as cursor:
#             sql = """
#                 INSERT INTO documents (title, category, sub_category, tags, file_path, extracted_data)
#                 VALUES (%s, %s, %s, %s, %s, %s)
#             """
#             params = (
#                 form_data.get("title"),
#                 form_data.get("category"),
#                 form_data.get("sub_category"),
#                 form_data.get("tags"),
#                 file_url,
#                 edited_data_json_str,
#             )
#             cursor.execute(sql, params)
#         connection.commit()

#         log_user_activity(
#             session.get("admin_id") or session.get("subadmin_id"),
#             session.get("admin_name") or session.get("subadmin_name"),
#             session.get("user_type"),
#             "Create",
#             "Documents/Submit",
#             f"Saved new document '{form_data.get('title')}' with S3 URL: {file_url}"
#         )

#         # Clean up the local temporary file
#         os.remove(filepath)
#         session.pop("processing_filepath", None)
#         session.pop("form_data_for_submission", None)
#         session.pop("processing_filename", None)

#         return jsonify({"message": "Document and extracted data saved successfully!"})
#     except Exception as e:
#         connection.rollback()
#         current_app.logger.error(f"An unexpected error occurred during submission: {e}")
#         # Attempt to clean up the temp file even on error
#         if filepath and os.path.exists(filepath):
#             os.remove(filepath)
#         return jsonify({"error": f"An internal error occurred during submission: {str(e)}"}), 500
#     finally:
#         connection.close()


# @main.route("/documents/submit", methods=["POST"])
# @adm_login_required
# def submitDocument():
#     """
#     Handles the final submission after the user has reviewed and edited the extracted data.
#     """
#     filepath = session.get("processing_filepath")
#     form_data = session.get("form_data_for_submission")
#     original_filename = session.get("processing_filename")

#     if not filepath or not form_data or not original_filename:
#         return jsonify({"error": "Analysis data not found. Please re-analyze the document."}), 400

#     edited_data_json_str = request.form.get("extracted_data")
#     if not edited_data_json_str:
#         return jsonify({"error": "No extracted data provided for submission."}), 400

#     try:
#         json.loads(edited_data_json_str)
#     except json.JSONDecodeError:
#         return jsonify({"error": "Invalid JSON format in the extracted data."}), 400

#     connection = get_db_connection()
#     try:
#         file_url = None
#         # Use the file from the session's temporary path for S3 upload
#         with open(filepath, 'rb') as f:
#             # CHANGED: We now pass the original filename directly to our helper
#             file_url = upload_file_to_s3(f, current_app.config.get("AWS_S3_BUCKET"), original_filename)

#         if not file_url:
#             raise Exception("Failed to upload file to S3.")

#         with connection.cursor() as cursor:
#             sql = """
#                 INSERT INTO documents (title, category, sub_category, tags, file_path, extracted_data, ocr_engine, token_count)
#                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
#             """
#             params = (
#                 form_data.get("title"),
#                 form_data.get("category"),
#                 form_data.get("sub_category"),
#                 form_data.get("tags"),
#                 file_url,
#                 edited_data_json_str,
#                 form_data.get("ocr_engine"),
#                 form_data.get("token_count", 0) 
#             )
#             cursor.execute(sql, params)
#         connection.commit()

#         log_user_activity(
#             session.get("admin_id") or session.get("subadmin_id"),
#             session.get("admin_name") or session.get("subadmin_name"),
#             session.get("user_type"),
#             "Create",
#             "Documents/Submit",
#             f"Saved new document '{form_data.get('title')}' with S3 URL: {file_url}"
#         )
        
#         return jsonify({"message": "Document and extracted data saved successfully!"})

#     except Exception as e:
#         connection.rollback()
#         current_app.logger.error(f"An unexpected error occurred during submission: {e}")
#         return jsonify({"error": f"An internal error occurred during submission: {str(e)}"}), 500
#     finally:
#         # Clean up the local temporary file and session data
#         if filepath and os.path.exists(filepath):
#             os.remove(filepath)
#         session.pop("processing_filepath", None)
#         session.pop("form_data_for_submission", None)
#         session.pop("processing_filename", None)
#         connection.close()


@main.route("/documents/submit", methods=["POST"])
@adm_login_required
def submitDocument():
    """
    Handles the final submission after the user has reviewed and edited the extracted data.
    """
    filepath = session.get("processing_filepath")
    form_data = session.get("form_data_for_submission")
    # --- CHANGED: Get both filenames from the session ---
    original_filename = session.get("original_filename")
    unique_filename_for_s3 = session.get("unique_filename_for_s3")

    if not all([filepath, form_data, original_filename, unique_filename_for_s3]):
        return jsonify({"error": "Analysis data not found. Please re-analyze the document."}), 400

    edited_data_json_str = request.form.get("extracted_data")
    if not edited_data_json_str:
        return jsonify({"error": "No extracted data provided for submission."}), 400

    try:
        json.loads(edited_data_json_str)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format in the extracted data."}), 400

    connection = get_db_connection()
    try:
        file_url = None
        with open(filepath, 'rb') as f:
            # --- CHANGED: Upload to S3 using the UNIQUE filename ---
            file_url = upload_file_to_s3(f, current_app.config.get("AWS_S3_BUCKET"), unique_filename_for_s3)

        if not file_url:
            raise Exception("Failed to upload file to S3.")

        with connection.cursor() as cursor:
            # --- CHANGED: Added original_filename to the INSERT statement ---
            sql = """
                INSERT INTO documents (title, category, sub_category, tags, file_path, 
                                       extracted_data, ocr_engine, token_count, original_filename)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            params = (
                form_data.get("title"),
                form_data.get("category"),
                form_data.get("sub_category"),
                form_data.get("tags"),
                file_url,
                edited_data_json_str,
                form_data.get("ocr_engine"),
                form_data.get("token_count", 0),
                original_filename # The new value to save
            )
            cursor.execute(sql, params)
        connection.commit()

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            "Create",
            "Documents/Submit",
            f"Saved new document '{form_data.get('title')}' with S3 URL: {file_url}"
        )
        
        return jsonify({"message": "Document and extracted data saved successfully!"})

    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"An unexpected error occurred during submission: {e}")
        return jsonify({"error": f"An internal error occurred during submission: {str(e)}"}), 500
    finally:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        # --- CHANGED: Clear all new session variables ---
        session.pop("processing_filepath", None)
        session.pop("form_data_for_submission", None)
        session.pop("original_filename", None)
        session.pop("unique_filename_for_s3", None)
        connection.close()


# @main.route("/documents/list")
# @adm_login_required
# @subadmin_permission_required("DOCUMENTS.view_documents")
# def documentList():
#     search_query = request.args.get("search", "")
#     category_filter = request.args.get("category", "")
#     sub_category_filter = request.args.get("sub_category", "")
#     tags_filter = request.args.get("tags", "")

#     connection = get_db_connection()
#     documents = []
#     distinct_categories = []
#     distinct_sub_categories = []
#     distinct_tags = []
#     try:
#         with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#             base_sql = "SELECT id, title, category, sub_category, tags, description, file_path, DATE_FORMAT(created_at, '%d-%m-%Y %r') as formatted_date FROM documents"
#             conditions, params = [], []

#             if search_query:
#                 search_like = f"%{search_query}%"
#                 conditions.append(
#                     "(title LIKE %s OR description LIKE %s OR tags LIKE %s OR CAST(extracted_data AS CHAR) LIKE %s)"
#                 )
#                 params.extend([search_like, search_like, search_like, search_like])
#             if category_filter:
#                 conditions.append("category = %s")
#                 params.append(category_filter)
#             if sub_category_filter:
#                 conditions.append("sub_category = %s")
#                 params.append(sub_category_filter)
#             if tags_filter:
#                 conditions.append("tags = %s")
#                 params.append(tags_filter)

#             if conditions:
#                 base_sql += " WHERE " + " AND ".join(conditions)
#             base_sql += " ORDER BY created_at DESC"

#             cursor.execute(base_sql, tuple(params))
#             documents = cursor.fetchall()

#             cursor.execute(
#                 "SELECT DISTINCT category FROM documents WHERE category IS NOT NULL AND category != '' ORDER BY category"
#             )
#             distinct_categories = [row["category"] for row in cursor.fetchall()]
#             cursor.execute(
#                 "SELECT DISTINCT sub_category FROM documents WHERE sub_category IS NOT NULL AND sub_category != '' ORDER BY sub_category"
#             )
#             distinct_sub_categories = [row["sub_category"] for row in cursor.fetchall()]
#             cursor.execute(
#                 "SELECT DISTINCT tags FROM documents WHERE tags IS NOT NULL AND tags != '' ORDER BY tags"
#             )
#             distinct_tags = [row["tags"] for row in cursor.fetchall()]
#     except Exception as e:
#         current_app.logger.error(f"Error fetching document list: {e}")
#         flash("An error occurred while fetching documents.", "danger")
#     finally:
#         connection.close()

#     current_filters = {
#         "search": search_query,
#         "category": category_filter,
#         "sub_category": sub_category_filter,
#         "tags": tags_filter,
#     }
#     return render_template(
#         "documentsList.html",
#         documents=documents,
#         distinct_categories=distinct_categories,
#         distinct_sub_categories=distinct_sub_categories,
#         distinct_tags=distinct_tags,
#         current_filters=current_filters,
#     )

# @main.route("/documents/list")
# @adm_login_required
# @subadmin_permission_required("DOCUMENTS.view_documents")
# def documentList():
#     search_query = request.args.get("search", "")
#     category_filter = request.args.get("category", "")
#     sub_category_filter = request.args.get("sub_category", "")
#     tags_filter = request.args.get("tags", "")

#     connection = get_db_connection()
#     documents = []
#     distinct_categories = []
#     distinct_sub_categories = []
#     distinct_tags = []
#     try:
#         with connection.cursor() as cursor:
#             # CORRECTED: Removed DATE_FORMAT from the SQL query
#             base_sql = "SELECT id, title, category, sub_category, tags, description, file_path, created_at FROM documents"
#             conditions, params = [], []

#             if search_query:
#                 search_like = f"%{search_query}%"
#                 conditions.append(
#                     "(title LIKE %s OR description LIKE %s OR tags LIKE %s OR CAST(extracted_data AS CHAR) LIKE %s)"
#                 )
#                 params.extend([search_like, search_like, search_like, search_like])
#             if category_filter:
#                 conditions.append("category = %s")
#                 params.append(category_filter)
#             if sub_category_filter:
#                 conditions.append("sub_category = %s")
#                 params.append(sub_category_filter)
#             if tags_filter:
#                 conditions.append("tags = %s")
#                 params.append(tags_filter)

#             if conditions:
#                 base_sql += " WHERE " + " AND ".join(conditions)
#             base_sql += " ORDER BY created_at DESC"

#             cursor.execute(base_sql, tuple(params))
#             documents = cursor.fetchall()

#             # These other queries are fine
#             cursor.execute("SELECT DISTINCT category FROM documents WHERE category IS NOT NULL AND category != '' ORDER BY category")
#             distinct_categories = [row["category"] for row in cursor.fetchall()]
#             cursor.execute("SELECT DISTINCT sub_category FROM documents WHERE sub_category IS NOT NULL AND sub_category != '' ORDER BY sub_category")
#             distinct_sub_categories = [row["sub_category"] for row in cursor.fetchall()]
#             cursor.execute("SELECT DISTINCT tags FROM documents WHERE tags IS NOT NULL AND tags != '' ORDER BY tags")
#             distinct_tags = [row["tags"] for row in cursor.fetchall()]
#     except Exception as e:
#         current_app.logger.error(f"Error fetching document list: {e}")
#         flash("An error occurred while fetching documents.", "danger")
#     finally:
#         connection.close()

#     current_filters = {
#         "search": search_query,
#         "category": category_filter,
#         "sub_category": sub_category_filter,
#         "tags": tags_filter,
#     }
#     return render_template(
#         "documentsList.html",
#         documents=documents,
#         distinct_categories=distinct_categories,
#         distinct_sub_categories=distinct_sub_categories,
#         distinct_tags=distinct_tags,
#         current_filters=current_filters,
#     )




# now its closed for without page reloading function
# @main.route("/documents/list")
# @adm_login_required
# @subadmin_permission_required("DOCUMENTS.view_documents")
# def documentList():
#     search_query = request.args.get("search", "")
#     category_filter = request.args.get("category", "")
#     sub_category_filter = request.args.get("sub_category", "")
#     tags_filter = request.args.get("tags", "")
#     # New: Check if the user wants to use AI search
#     ai_search_enabled = request.args.get("ai_search") == "true"

#     connection = get_db_connection()
#     documents = []
#     distinct_categories = []
#     distinct_sub_categories = []
#     distinct_tags = []

#     try:
#         with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#             # The logic for fetching filter options remains the same
#             cursor.execute("SELECT DISTINCT category FROM documents WHERE category IS NOT NULL AND category != '' ORDER BY category")
#             distinct_categories = [row["category"] for row in cursor.fetchall()]
#             cursor.execute("SELECT DISTINCT sub_category FROM documents WHERE sub_category IS NOT NULL AND sub_category != '' ORDER BY sub_category")
#             distinct_sub_categories = [row["sub_category"] for row in cursor.fetchall()]
#             cursor.execute("SELECT DISTINCT tags FROM documents WHERE tags IS NOT NULL AND tags != '' ORDER BY tags")
#             distinct_tags = [row["tags"] for row in cursor.fetchall()]

#             # --- SEARCH LOGIC ---
#             # If AI Search is enabled AND there is a search query
#             if ai_search_enabled and search_query:
#                 flash("AI search is active. This may take a moment...", "info")
                
#                 # 1. Fetch all documents' ID and extracted data to be analyzed
#                 # Note: This could be slow on very large databases.
#                 # Consider adding your other filters (category, etc.) here to reduce the search space.
#                 cursor.execute("SELECT id, extracted_data FROM documents")
#                 all_docs_for_ai = cursor.fetchall()
                
#                 matching_ids = []
#                 for doc in all_docs_for_ai:
#                     # 2. For each document, ask OpenAI if it's relevant
#                     if is_document_relevant_openai(search_query, doc['extracted_data']):
#                         matching_ids.append(doc['id'])
                
#                 # 3. If any matches were found, fetch the full document details for display
#                 if matching_ids:
#                     # Using a placeholder for a list of IDs
#                     format_strings = ','.join(['%s'] * len(matching_ids))
#                     sql = f"SELECT * FROM documents WHERE id IN ({format_strings}) ORDER BY created_at DESC"
#                     cursor.execute(sql, tuple(matching_ids))
#                     documents = cursor.fetchall()
#                 else:
#                     # If AI found no matches, documents list will be empty
#                     documents = []

#             # --- Standard Keyword Search Logic (The original method) ---
#             else:
#                 base_sql = "SELECT * FROM documents"
#                 conditions, params = [], []

#                 if search_query:
#                     search_like = f"%{search_query}%"
#                     conditions.append(
#                         "(title LIKE %s OR description LIKE %s OR tags LIKE %s OR CAST(extracted_data AS CHAR) LIKE %s OR original_filename LIKE %s)"
#                     )
#                     params.extend([search_like, search_like, search_like, search_like, search_like])
                
#                 # Filters are applied in both search modes
#                 if category_filter:
#                     conditions.append("category = %s")
#                     params.append(category_filter)
#                 if sub_category_filter:
#                     conditions.append("sub_category = %s")
#                     params.append(sub_category_filter)
#                 if tags_filter:
#                     conditions.append("tags = %s")
#                     params.append(tags_filter)

#                 if conditions:
#                     base_sql += " WHERE " + " AND ".join(conditions)
                
#                 base_sql += " ORDER BY created_at DESC"
#                 cursor.execute(base_sql, tuple(params))
#                 documents = cursor.fetchall()

#     except Exception as e:
#         current_app.logger.error(f"Error fetching document list: {e}")
#         flash("An error occurred while fetching documents.", "danger")
#     finally:
#         connection.close()

#     current_filters = {
#         "search": search_query,
#         "category": category_filter,
#         "sub_category": sub_category_filter,
#         "tags": tags_filter,
#         "ai_search": ai_search_enabled, # Pass the AI search status to the template
#     }
#     return render_template(
#         "documentsList.html",
#         documents=documents,
#         distinct_categories=distinct_categories,
#         distinct_sub_categories=distinct_sub_categories,
#         distinct_tags=distinct_tags,
#         current_filters=current_filters,
#     )



# new for without page reloading 
@main.route("/documents/list")
@adm_login_required
@subadmin_permission_required("DOCUMENTS.view_documents")
def documentList():
    """Renders the main documents list page. Data will be loaded via JavaScript."""
    connection = get_db_connection()
    distinct_categories = []
    distinct_sub_categories = []
    distinct_tags = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            # Fetch filter options to populate the dropdowns initially
            cursor.execute("SELECT DISTINCT category FROM documents WHERE category IS NOT NULL AND category != '' ORDER BY category")
            distinct_categories = [row["category"] for row in cursor.fetchall()]
            cursor.execute("SELECT DISTINCT sub_category FROM documents WHERE sub_category IS NOT NULL AND sub_category != '' ORDER BY sub_category")
            distinct_sub_categories = [row["sub_category"] for row in cursor.fetchall()]
            cursor.execute("SELECT DISTINCT tags FROM documents WHERE tags IS NOT NULL AND tags != '' ORDER BY tags")
            distinct_tags = [row["tags"] for row in cursor.fetchall()]
    except Exception as e:
        current_app.logger.error(f"Error fetching filter options: {e}")
        flash("An error occurred while fetching filter options.", "danger")
    finally:
        connection.close()

    return render_template(
        "documentsList.html",
        documents=[],  # Start with an empty list; JS will fetch the data
        distinct_categories=distinct_categories,
        distinct_sub_categories=distinct_sub_categories,
        distinct_tags=distinct_tags,
    )

@main.route("/api/search-documents")
@adm_login_required
def api_search_documents():
    """API endpoint to fetch and filter documents, returns JSON."""
    search_query = request.args.get("search", "")
    category_filter = request.args.get("category", "")
    sub_category_filter = request.args.get("sub_category", "")
    tags_filter = request.args.get("tags", "")

    connection = get_db_connection()
    documents = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            base_sql = "SELECT * FROM documents"
            conditions, params = [], []

            if search_query:
                search_like = f"%{search_query}%"
                conditions.append(
                    "(title LIKE %s OR description LIKE %s OR tags LIKE %s OR CAST(extracted_data AS CHAR) LIKE %s OR original_filename LIKE %s)"
                )
                params.extend([search_like, search_like, search_like, search_like, search_like])
            
            if category_filter:
                conditions.append("category = %s")
                params.append(category_filter)
            if sub_category_filter:
                conditions.append("sub_category = %s")
                params.append(sub_category_filter)
            if tags_filter:
                conditions.append("tags = %s")
                params.append(tags_filter)

            if conditions:
                base_sql += " WHERE " + " AND ".join(conditions)
            
            base_sql += " ORDER BY created_at DESC"
            cursor.execute(base_sql, tuple(params))
            documents = cursor.fetchall()
            
            # Convert datetime objects to strings for JSON compatibility
            for doc in documents:
                if 'created_at' in doc and doc['created_at']:
                    doc['created_at'] = doc['created_at'].strftime('%d-%m-%Y %I:%M %p')

    except Exception as e:
        current_app.logger.error(f"Error fetching document list via API: {e}")
        return jsonify({"error": "An error occurred while fetching documents."}), 500
    finally:
        connection.close()
        
    return jsonify(documents)

# @main.route("/documents/edit/<int:doc_id>", methods=["GET", "POST"])
# @adm_login_required
# @subadmin_permission_required("DOCUMENTS.edit_document")
# def editDocument(doc_id):
#     connection = get_db_connection()
#     doc = None
#     try:
#         if request.method == "POST":
#             form_data = request.form
#             title = form_data.get("title")
#             if not title:
#                 flash("Title is a required field.", "error")
#                 with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#                     cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
#                     doc = cursor.fetchone()
#                 return render_template("editDocument.html", doc=doc)
            
#             with connection.cursor() as cursor:
#                 sql = """
#                     UPDATE documents
#                     SET title = %s, category = %s, sub_category = %s, tags = %s, description = %s
#                     WHERE id = %s
#                 """
#                 params = (
#                     form_data.get("title"),
#                     form_data.get("category"),
#                     form_data.get("sub_category"),
#                     form_data.get("tags"),
#                     form_data.get("description"),
#                     doc_id,
#                 )
#                 cursor.execute(sql, params)
#             connection.commit()

#             log_user_activity(
#                 session.get("admin_id") or session.get("subadmin_id"),
#                 session.get("admin_name") or session.get("subadmin_name"),
#                 session.get("user_type"),
#                 "Edit",
#                 "Documents/Edit",
#                 f"Edited document '{title}' with ID: {doc_id}"
#             )

#             flash("Document updated successfully!", "success")
#             return redirect(url_for("main.documentList"))
#         else:
#             with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#                 cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
#                 doc = cursor.fetchone()
#                 if not doc:
#                     flash("Document not found.", "error")
#                     return redirect(url_for("main.documentList"))
#             return render_template("editDocument.html", doc=doc)
#     except Exception as e:
#         connection.rollback()
#         current_app.logger.error(f"An unexpected error occurred: {e}")
#         flash("An error occurred while editing the document.", "danger")
#     finally:
#         connection.close()
#     return redirect(url_for("main.documentList"))


# @main.route("/documents/edit/<int:doc_id>", methods=["GET", "POST"])
# @adm_login_required
# @subadmin_permission_required("DOCUMENTS.edit_document")
# def editDocument(doc_id):
#     connection = get_db_connection()
#     try:
#         if request.method == "POST":
#             form_data = request.form
#             title = form_data.get("title")
#             extracted_data_str = form_data.get("extracted_data")

#             if not title:
#                 flash("Title is a required field.", "error")
#                 # Refetch doc data to repopulate the form on error
#                 with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#                     cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
#                     doc = cursor.fetchone()
#                 return render_template("editDocument.html", doc=doc)

#             # Validate if the extracted_data is valid JSON before saving
#             try:
#                 json.loads(extracted_data_str)
#             except json.JSONDecodeError:
#                 flash("Error: Extracted data is not in a valid JSON format.", "danger")
#                 with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#                     cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
#                     doc = cursor.fetchone()
#                     # Keep the user's invalid text to let them fix it
#                     doc['extracted_data'] = extracted_data_str 
#                 return render_template("editDocument.html", doc=doc)
            
#             with connection.cursor() as cursor:
#                 # UPDATED SQL: Removed 'description' and added 'extracted_data'
#                 sql = """
#                     UPDATE documents
#                     SET title = %s, category = %s, sub_category = %s, tags = %s, extracted_data = %s
#                     WHERE id = %s
#                 """
#                 params = (
#                     title,
#                     form_data.get("category"),
#                     form_data.get("sub_category"),
#                     form_data.get("tags"),
#                     extracted_data_str, # New data from the form
#                     doc_id,
#                 )
#                 cursor.execute(sql, params)
#             connection.commit()

#             log_user_activity(
#                 session.get("admin_id") or session.get("subadmin_id"),
#                 session.get("admin_name") or session.get("subadmin_name"),
#                 session.get("user_type"),
#                 "Edit",
#                 "Documents/Edit",
#                 f"Edited document '{title}' with ID: {doc_id}"
#             )

#             flash("Document updated successfully!", "success")
#             return redirect(url_for("main.documentList"))
        
#         else: # GET request
#             with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#                 cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
#                 doc = cursor.fetchone()
#                 if not doc:
#                     flash("Document not found.", "error")
#                     return redirect(url_for("main.documentList"))
                
#                 # Pretty-print the JSON for better readability in the textarea
#                 try:
#                     parsed_json = json.loads(doc['extracted_data'])
#                     doc['extracted_data'] = json.dumps(parsed_json, indent=4)
#                 except (json.JSONDecodeError, TypeError):
#                     # If data is not valid JSON, display it as is
#                     pass
                    
#             return render_template("editDocument.html", doc=doc)

#     except Exception as e:
#         connection.rollback()
#         current_app.logger.error(f"An unexpected error occurred: {e}")
#         flash("An error occurred while editing the document.", "danger")
#         return redirect(url_for("main.documentList"))
#     finally:
#         if connection:
#             connection.close()

# REPLACE your existing editDocument function with this one

@main.route("/documents/edit/<int:doc_id>", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("DOCUMENTS.edit_document")
def editDocument(doc_id):
    connection = get_db_connection()
    try:
        if request.method == "POST":
            # --- This POST logic remains unchanged ---
            form_data = request.form
            title = form_data.get("title")
            extracted_data_str = form_data.get("extracted_data")

            if not title:
                flash("Title is a required field.", "error")
                with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                    cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
                    doc = cursor.fetchone()
                return render_template("editDocument.html", doc=doc)

            try:
                json.loads(extracted_data_str)
            except json.JSONDecodeError:
                flash("Error: Extracted data is not in a valid JSON format.", "danger")
                with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                    cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
                    doc = cursor.fetchone()
                    doc['extracted_data'] = extracted_data_str 
                return render_template("editDocument.html", doc=doc)
            
            with connection.cursor() as cursor:
                sql = "UPDATE documents SET title = %s, category = %s, sub_category = %s, tags = %s, extracted_data = %s WHERE id = %s"
                params = (title, form_data.get("category"), form_data.get("sub_category"), form_data.get("tags"), extracted_data_str, doc_id)
                cursor.execute(sql, params)
            connection.commit()

            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"), "Edit", "Documents/Edit",
                f"Edited document '{title}' with ID: {doc_id}"
            )
            flash("Document updated successfully!", "success")
            return redirect(url_for("main.documentList"))
        
        else: # --- THIS GET LOGIC IS UPDATED ---
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                # 1. Fetch the specific document to edit
                cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
                doc = cursor.fetchone()
                if not doc:
                    flash("Document not found.", "error")
                    return redirect(url_for("main.documentList"))
                
                # Pretty-print the JSON for readability
                try:
                    parsed_json = json.loads(doc['extracted_data'])
                    doc['extracted_data'] = json.dumps(parsed_json, indent=4)
                except (json.JSONDecodeError, TypeError):
                    pass
                
                # 2. Fetch all options for the dropdowns
                cursor.execute("SELECT category_name FROM categories ORDER BY category_name ASC")
                all_categories = cursor.fetchall()
                cursor.execute("SELECT sub_category_name FROM sub_categories ORDER BY sub_category_name ASC")
                all_subcategories = cursor.fetchall()
                cursor.execute("SELECT tag_name FROM tags ORDER BY tag_name ASC")
                all_tags = cursor.fetchall()
                    
            return render_template(
                "editDocument.html", 
                doc=doc,
                categories=all_categories,
                subcategories=all_subcategories,
                tags=all_tags
            )

    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"An unexpected error occurred: {e}")
        flash("An error occurred while editing the document.", "danger")
        return redirect(url_for("main.documentList"))
    finally:
        if connection:
            connection.close()

            
@main.route("/documents/delete/<int:doc_id>", methods=["POST"])
@adm_login_required
@subadmin_permission_required("DOCUMENTS.delete_document")
def deleteDocument(doc_id):
    connection = get_db_connection()
    file_path = None
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT file_path FROM documents WHERE id = %s", (doc_id,))
            doc = cursor.fetchone()

            if not doc:
                flash("Document not found.", "error")
                return redirect(url_for("main.documentList"))
            
            file_path = doc.get("file_path")
            
            cursor.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
        connection.commit()

        # Extract the key (filename) from the S3 URL
        if file_path:
            file_key = file_path.split("/")[-1]
            delete_file_from_s3(file_key, current_app.config.get("AWS_S3_BUCKET"))

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            "Delete",
            "Documents/Delete",
            f"Deleted document with ID: {doc_id}"
        )

        flash("Document deleted successfully!", "success")
    except Exception as e:
        connection.rollback()
        flash(f"An error occurred: {str(e)}", "error")
    finally:
        connection.close()
    return redirect(url_for("main.documentList"))


# # ---------------------------------------------------------------------
# # User Management Routes
# # ---------------------------------------------------------------------


@main.route("/users/roles")
@adm_login_required
@subadmin_permission_required("ROLES.view_roles")
def usersRoles():
    """
    Displays a list of all roles. This is the main roles page.
    """
    connection = get_db_connection()
    all_roles = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT r_id, role_name, permissions, DATE_FORMAT(r_created_at, '%d-%m-%Y %r') AS r_created_at FROM subadminroles ORDER BY r_created_at ASC"
            )
            all_roles = cursor.fetchall()
        return render_template("usersRoles.html", all_roles=all_roles)
    except Exception as e:
        current_app.logger.error(f"Error fetching roles: {e}")
        flash("An error occurred while fetching roles.", "danger")
        return render_template("usersRoles.html", all_roles=[])
    finally:
        connection.close()


@main.route("/users/roles/create", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("ROLES.create_role")
def createRole():
    """
    Handles the creation of a new role.
    GET: Displays the role creation form.
    POST: Processes the form and creates the new role.
    """
    if request.method == "POST":
        role_name = request.form.get("role_name")
        if not role_name:
            flash("Role name is required.", "danger")
            return redirect(url_for("main.createRole"))

        permissions = {
            "CATEGORIES": {
                "view_categories": request.form.get("view_categories", "No"),
                "create_category": request.form.get("create_category", "No"),
                "edit_category": request.form.get("edit_category", "No"),
                "delete_category": request.form.get("delete_category", "No"),
            },
            "SUB_CATEGORIES": {
                "view_sub_categories": request.form.get("view_sub_categories", "No"),
                "create_sub_category": request.form.get("create_sub_category", "No"),
                "edit_sub_category": request.form.get("edit_sub_category", "No"),
                "delete_sub_category": request.form.get("delete_sub_category", "No"),
            },
            "TAGS": {
                "view_tags": request.form.get("view_tags", "No"),
                "create_tag": request.form.get("create_tag", "No"),
                "edit_tag": request.form.get("edit_tag", "No"),
                "delete_tag": request.form.get("delete_tag", "No"),
            },
            "DOCUMENTS": {
                "view_documents": request.form.get("view_documents", "No"),
                "create_document": request.form.get("create_document", "No"),
                "edit_document": request.form.get("edit_document", "No"),
                "delete_document": request.form.get("delete_document", "No"),
            },
            "ROLES": {
                "view_roles": request.form.get("view_roles", "No"),
                "create_role": request.form.get("create_role", "No"),
                "edit_role": request.form.get("edit_role", "No"),
                "delete_role": request.form.get("delete_role", "No"),
            },
            "USERS": {
                "view_users": request.form.get("view_users", "No"),
                "create_users": request.form.get("create_users", "No"),
                "edit_users": request.form.get("edit_users", "No"),
                "delete_users": request.form.get("delete_users", "No"),
            },
            "USER_ACTIVITIES": {
                "view_user_activities": request.form.get("view_user_activities", "No"),
            },
            "DASHBOARDS": {
                "view_dashboard": request.form.get("view_dashboard", "No"),
            },
        }
        permissions_json = json.dumps(permissions)

        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                sql = "INSERT INTO subadminroles (role_name, permissions) VALUES (%s, %s)"
                cursor.execute(sql, (role_name, permissions_json))
            connection.commit()

            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                "Create",
                "Users/Roles",
                f"Created new role '{role_name}'"
            )

            flash(f'Role "{role_name}" created successfully!', "success")
            return redirect(url_for("main.usersRoles"))
        except pymysql.err.IntegrityError:
            connection.rollback()
            flash(f'A role with the name "{role_name}" already exists.', "danger")
            return redirect(url_for("main.createRole"))
        except Exception as e:
            connection.rollback()
            current_app.logger.error(f"Error creating role: {e}")
            flash("An error occurred while creating the role.", "danger")
            return redirect(url_for("main.createRole"))
        finally:
            connection.close()

    return render_template("create_edit_role.html", role=None)


@main.route("/users/roles/edit/<int:role_id>", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("ROLES.edit_role")
def editRole(role_id):
    """
    Handles editing an existing role.
    GET: Fetches role data and displays it in the form.
    POST: Processes the form and updates the role.
    """
    connection = get_db_connection()
    try:
        if request.method == "POST":
            role_name = request.form.get("role_name")
            permissions = {
                "CATEGORIES": {
                    "view_categories": request.form.get("view_categories", "No"),
                    "create_category": request.form.get("create_category", "No"),
                    "edit_category": request.form.get("edit_category", "No"),
                    "delete_category": request.form.get("delete_category", "No"),
                },
                "SUB_CATEGORIES": {
                    "view_sub_categories": request.form.get("view_sub_categories", "No"),
                    "create_sub_category": request.form.get("create_sub_category", "No"),
                    "edit_sub_category": request.form.get("edit_sub_category", "No"),
                    "delete_sub_category": request.form.get("delete_sub_category", "No"),
                },
                "TAGS": {
                    "view_tags": request.form.get("view_tags", "No"),
                    "create_tag": request.form.get("create_tag", "No"),
                    "edit_tag": request.form.get("edit_tag", "No"),
                    "delete_tag": request.form.get("delete_tag", "No"),
                },
                "DOCUMENTS": {
                    "view_documents": request.form.get("view_documents", "No"),
                    "create_document": request.form.get("create_document", "No"),
                    "edit_document": request.form.get("edit_document", "No"),
                    "delete_document": request.form.get("delete_document", "No"),
                },
                "ROLES": {
                    "view_roles": request.form.get("view_roles", "No"),
                    "create_role": request.form.get("create_role", "No"),
                    "edit_role": request.form.get("edit_role", "No"),
                    "delete_role": request.form.get("delete_role", "No"),
                },
                "USERS": {
                    "view_users": request.form.get("view_users", "No"),
                    "create_users": request.form.get("create_users", "No"),
                    "edit_users": request.form.get("edit_users", "No"),
                    "delete_users": request.form.get("delete_users", "No"),
                },
                "USER_ACTIVITIES": {
                    "view_user_activities": request.form.get("view_user_activities", "No"),
                },
                "DASHBOARDS": {
                    "view_dashboard": request.form.get("view_dashboard", "No"),
                },
            }
            permissions_json = json.dumps(permissions)

            with connection.cursor() as cursor:
                update_sql = "UPDATE subadminroles SET role_name = %s, permissions = %s WHERE r_id = %s"
                cursor.execute(update_sql, (role_name, permissions_json, role_id))

            connection.commit()

            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                "Edit",
                "Users/Roles",
                f"Edited role '{role_name}' with ID: {role_id}"
            )

            flash(f'Role "{role_name}" updated successfully!', "success")
            return redirect(url_for("main.usersRoles"))

        else: # GET request
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "SELECT r_id, role_name, permissions FROM subadminroles WHERE r_id = %s",
                    (role_id,),
                )
                role = cursor.fetchone()
                if not role:
                    flash("Role not found.", "danger")
                    return redirect(url_for("main.usersRoles"))
                role["permissions"] = json.loads(role["permissions"])
            return render_template("create_edit_role.html", role=role)

    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"Error editing role {role_id}: {e}")
        flash("An error occurred while editing the role.", "danger")
        return redirect(url_for("main.usersRoles"))
    finally:
        connection.close()


@main.route("/users/roles/delete/<int:role_id>", methods=["POST"])
@adm_login_required
@subadmin_permission_required("ROLES.delete_role")
def deleteRole(role_id):
    """
    Deletes a role.
    Prevents deletion if the role is assigned to any user.
    """
    connection = get_db_connection()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT COUNT(*) as user_count FROM subadmin WHERE role_id = %s", (role_id,)
            )
            result = cursor.fetchone()

            if result and result["user_count"] > 0:
                flash(
                    f'Cannot delete this role. It is currently assigned to {result["user_count"]} user(s).',
                    "danger",
                )
                return redirect(url_for("main.usersRoles"))

            cursor.execute(
                "SELECT role_name FROM subadminroles WHERE r_id = %s", (role_id,)
            )
            role = cursor.fetchone()
            role_name = role["role_name"] if role else "Unknown"

            cursor.execute("DELETE FROM subadminroles WHERE r_id = %s", (role_id,))
        connection.commit()

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            "Delete",
            "Users/Roles",
            f"Deleted role '{role_name}' with ID: {role_id}"
        )

        flash(f'Role "{role_name}" has been deleted.', "success")

    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"Error deleting role {role_id}: {e}")
        flash("An error occurred while deleting the role.", "danger")

    finally:
        connection.close()

    return redirect(url_for("main.usersRoles"))


# # =====================================================================
# # User Management Routes
# # =====================================================================


@main.route("/users/list")
@adm_login_required
@subadmin_permission_required("USERS.view_users")
def userList():
    """
    Displays a list of all users with their assigned roles.
    """
    connection = get_db_connection()
    all_users = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = """
                SELECT s.subadmin_id, s.subadmin_name, s.subadmin_email, s.subadmin_username,
                COALESCE(r.role_name, 'No Role') AS role_name,
                DATE_FORMAT(s.u_created_at, '%d-%m-%Y %r') AS u_created_at
                FROM subadmin s
                LEFT JOIN subadminroles r ON s.role_id = r.r_id
                ORDER BY s.u_created_at ASC
            """
            cursor.execute(sql)
            all_users = cursor.fetchall()
        return render_template("usersList.html", all_users=all_users)
    except Exception as e:
        current_app.logger.error(f"Error fetching users: {e}")
        flash("An error occurred while fetching users.", "danger")
        return render_template("usersList.html", all_users=[])
    finally:
        connection.close()


# @main.route("/users/create", methods=["GET", "POST"])
# @adm_login_required
# @subadmin_permission_required("USERS.create_users")
# def createUser():
#     """
#     Handles the creation of a new user.
#     """
#     connection = get_db_connection()
    
#     try:
#         if request.method == "POST":
#             name = request.form.get("name")
#             email = request.form.get("email")
#             username = request.form.get("username")
#             password = request.form.get("password")
#             confirm_password = request.form.get("confirm_password")
#             role_id = request.form.get("role_id")
#             role_name = request.form.get("role_name")

#             if not all([name, email, username, password, confirm_password, role_id]):
#                 flash("All fields are required.", "danger")
#                 return redirect(url_for("main.createUser"))

#             if password != confirm_password:
#                 flash("Passwords do not match.", "danger")
#                 return redirect(url_for("main.createUser"))

#             hashed_password = bcrypt.hashpw(
#                 password.encode("utf-8"), bcrypt.gensalt()
#             ).decode("utf-8")
            
#             with connection.cursor() as cursor:
#                 cursor.execute("SELECT * FROM superadmin WHERE superadmin_email=%s", (email,))
#                 if cursor.fetchone():
#                     flash(f'Email "{email}" already exist in super admin portal . Please choose another.')
                
#                 cursor.execute("SELECT * FROM admin WHERE admin_email=%s", (email,))
#                 if cursor.fetchone():
#                     flash(f'Email "{email}" already exist in admin portal . Please choose another.')

#             with connection.cursor() as cursor:
#                 sql = "INSERT INTO subadmin (subadmin_name, subadmin_email, subadmin_username, subadmin_password, role_id) VALUES (%s, %s, %s, %s, %s)"
#                 cursor.execute(sql, (name, email, username, hashed_password, role_id))
#             connection.commit()

#             log_user_activity(
#                 session.get("admin_id") or session.get("subadmin_id"),
#                 session.get("admin_name") or session.get("subadmin_name"),
#                 session.get("user_type"),
#                 "Create",
#                 "Users/User Management",
#                 f"Created new user '{name}' with email '{email}' and role_id '{role_id}'"
#             )

#             flash(f'User "{name}" created successfully!', "success")
#             return redirect(url_for("main.userList"))

#         # For GET request, fetch roles to populate the dropdown
#         with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#             cursor.execute(
#                 "SELECT r_id, role_name FROM subadminroles ORDER BY role_name ASC"
#             )
#             all_roles = cursor.fetchall()
#         return render_template("create_edit_user.html", user=None, all_roles=all_roles)

#     except pymysql.err.IntegrityError as e:
#         connection.rollback()
#         if "email" in str(e).lower():
#             flash(f'An account with the email "{email}" already exists.', "danger")
#         elif "username" in str(e).lower():
#             flash(f'An account with the username "{username}" already exists.', "danger")
#         else:
#             flash("A database error occurred. The username or email might already be taken.", "danger")
#         return redirect(url_for("main.createUser"))
#     except Exception as e:
#         connection.rollback()
#         current_app.logger.error(f"Error creating user: {e}")
#         flash("An error occurred while creating the user.", "danger")
#         return redirect(url_for("main.createUser"))
#     finally:
#         connection.close()

@main.route("/users/create", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("USERS.create_users")
def createUser():
    """
    Handles the creation of a new user.
    """
    connection = get_db_connection()
    
    try:
        if request.method == "POST":
            name = request.form.get("name")
            email = request.form.get("email")
            username = request.form.get("username")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")
            role_id = request.form.get("role_id")

            if not all([name, email, username, password, confirm_password, role_id]):
                flash("All fields are required.", "danger")
                return redirect(url_for("main.createUser"))

            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return redirect(url_for("main.createUser"))

            # Check email uniqueness across ALL user tables
            with connection.cursor() as cursor:
                # Check superadmin table
                cursor.execute("SELECT superadmin_email FROM superadmin WHERE superadmin_email=%s", (email,))
                if cursor.fetchone():
                    flash(f'Email "{email}" already exists in super admin portal. Please choose another.', "danger")
                    return redirect(url_for("main.createUser"))
                
                # Check admin table
                cursor.execute("SELECT admin_email FROM admin WHERE admin_email=%s", (email,))
                if cursor.fetchone():
                    flash(f'Email "{email}" already exists in admin portal. Please choose another.', "danger")
                    return redirect(url_for("main.createUser"))
                
                # Check subadmin table (the table we're inserting into)
                cursor.execute("SELECT subadmin_email FROM subadmin WHERE subadmin_email=%s", (email,))
                if cursor.fetchone():
                    flash(f'Email "{email}" already exists in subadmin portal. Please choose another.', "danger")
                    return redirect(url_for("main.createUser"))
                
                # Check username uniqueness in subadmin table
                cursor.execute("SELECT subadmin_username FROM subadmin WHERE subadmin_username=%s", (username,))
                if cursor.fetchone():
                    flash(f'Username "{username}" is already taken. Please choose another.', "danger")
                    return redirect(url_for("main.createUser"))

            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
            
            # Insert the new user
            with connection.cursor() as cursor:
                sql = "INSERT INTO subadmin (subadmin_name, subadmin_email, subadmin_username, subadmin_password, role_id) VALUES (%s, %s, %s, %s, %s)"
                cursor.execute(sql, (name, email, username, hashed_password, role_id))
            connection.commit()

            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                "Create",
                "Users/User Management",
                f"Created new user '{name}' with email '{email}' and role_id '{role_id}'"
            )

            flash(f'User "{name}" created successfully!', "success")
            return redirect(url_for("main.userList"))

        # For GET request, fetch roles to populate the dropdown
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT r_id, role_name FROM subadminroles ORDER BY role_name ASC"
            )
            all_roles = cursor.fetchall()
        return render_template("create_edit_user.html", user=None, all_roles=all_roles)

    except pymysql.err.IntegrityError as e:
        connection.rollback()
        if "email" in str(e).lower():
            flash(f'An account with the email "{email}" already exists.', "danger")
        elif "username" in str(e).lower():
            flash(f'An account with the username "{username}" already exists.', "danger")
        else:
            flash("A database error occurred. The username or email might already be taken.", "danger")
        return redirect(url_for("main.createUser"))
    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"Error creating user: {e}")
        flash("An error occurred while creating the user.", "danger")
        return redirect(url_for("main.createUser"))
    finally:
        connection.close()


# @main.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
# @adm_login_required
# @subadmin_permission_required("USERS.edit_users")
# def editUser(user_id):
#     """
#     Handles editing an existing user.
#     """
#     connection = get_db_connection()
#     try:
#         if request.method == "POST":
#             name = request.form.get("name")
#             email = request.form.get("email")
#             username = request.form.get("username")
#             password = request.form.get("password")
#             confirm_password = request.form.get("confirm_password")
#             role_id = request.form.get("role_id")

#             with connection.cursor() as cursor:
#                 if password:
#                     if password != confirm_password:
#                         flash("New passwords do not match.", "danger")
#                         return redirect(url_for("main.editUser", user_id=user_id))
                        
#                     hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                    
#                     sql = "UPDATE subadmin SET subadmin_name=%s, subadmin_email=%s, subadmin_username=%s, subadmin_password=%s, role_id=%s WHERE subadmin_id=%s"
#                     cursor.execute(
#                         sql, (name, email, username, hashed_password, role_id, user_id)
#                     )
#                 else:
#                     sql = "UPDATE subadmin SET subadmin_name=%s, subadmin_email=%s, subadmin_username=%s, role_id=%s WHERE subadmin_id=%s"
#                     cursor.execute(sql, (name, email, username, role_id, user_id))
        
#             connection.commit()
            
#             log_user_activity(
#                 session.get("admin_id") or session.get("subadmin_id"),
#                 session.get("admin_name") or session.get("subadmin_name"),
#                 session.get("user_type"),
#                 "Edit",
#                 "Users/User Management",
#                 f"Edited user '{name}' with ID: {user_id}"
#             )
            
#             flash(f'User "{name}" updated successfully!', "success")
#             return redirect(url_for("main.userList"))

#         else: # GET request
#             with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#                 cursor.execute("SELECT * FROM subadmin WHERE subadmin_id = %s", (user_id,))
#                 user = cursor.fetchone()
#                 if not user:
#                     flash("User not found.", "danger")
#                     return redirect(url_for("main.userList"))

#                 cursor.execute("SELECT r_id, role_name FROM subadminroles ORDER BY role_name ASC")
#                 all_roles = cursor.fetchall()
                
#             return render_template("create_edit_user.html", user=user, all_roles=all_roles)

#     except pymysql.err.IntegrityError:
#         connection.rollback()
#         flash("That email or username is already in use by another account.", "danger")
#         return redirect(url_for("main.editUser", user_id=user_id))
#     except Exception as e:
#         connection.rollback()
#         current_app.logger.error(f"Error editing user {user_id}: {e}")
#         flash("An error occurred while editing the user.", "danger")
#         return redirect(url_for("main.userList"))
#     finally:
#         connection.close()

@main.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("USERS.edit_users")
def editUser(user_id):
    """
    Handles editing an existing user.
    """
    connection = get_db_connection()
    try:
        if request.method == "POST":
            name = request.form.get("name")
            email = request.form.get("email")
            username = request.form.get("username")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")
            role_id = request.form.get("role_id")

            # Validate required fields
            if not all([name, email, username, role_id]):
                flash("All fields except password are required.", "danger")
                return redirect(url_for("main.editUser", user_id=user_id))

            if password and password != confirm_password:
                flash("New passwords do not match.", "danger")
                return redirect(url_for("main.editUser", user_id=user_id))

            # Check email uniqueness across ALL user tables (excluding current user)
            with connection.cursor() as cursor:
                # Check superadmin table
                cursor.execute("SELECT superadmin_email FROM superadmin WHERE superadmin_email=%s", (email,))
                if cursor.fetchone():
                    flash(f'Email "{email}" already exists in super admin portal. Please choose another.', "danger")
                    return redirect(url_for("main.editUser", user_id=user_id))
                
                # Check admin table
                cursor.execute("SELECT admin_email FROM admin WHERE admin_email=%s", (email,))
                if cursor.fetchone():
                    flash(f'Email "{email}" already exists in admin portal. Please choose another.', "danger")
                    return redirect(url_for("main.editUser", user_id=user_id))
                
                # Check subadmin table (excluding current user)
                cursor.execute("SELECT subadmin_id, subadmin_email FROM subadmin WHERE subadmin_email=%s AND subadmin_id != %s", (email, user_id))
                if cursor.fetchone():
                    flash(f'Email "{email}" already exists in subadmin portal. Please choose another.', "danger")
                    return redirect(url_for("main.editUser", user_id=user_id))
                
                # Check username uniqueness in subadmin table (excluding current user)
                cursor.execute("SELECT subadmin_id, subadmin_username FROM subadmin WHERE subadmin_username=%s AND subadmin_id != %s", (username, user_id))
                if cursor.fetchone():
                    flash(f'Username "{username}" is already taken. Please choose another.', "danger")
                    return redirect(url_for("main.editUser", user_id=user_id))

            # Update the user
            with connection.cursor() as cursor:
                if password:
                    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                    
                    sql = "UPDATE subadmin SET subadmin_name=%s, subadmin_email=%s, subadmin_username=%s, subadmin_password=%s, role_id=%s WHERE subadmin_id=%s"
                    cursor.execute(
                        sql, (name, email, username, hashed_password, role_id, user_id)
                    )
                else:
                    sql = "UPDATE subadmin SET subadmin_name=%s, subadmin_email=%s, subadmin_username=%s, role_id=%s WHERE subadmin_id=%s"
                    cursor.execute(sql, (name, email, username, role_id, user_id))
        
            connection.commit()
            
            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                "Edit",
                "Users/User Management",
                f"Edited user '{name}' with ID: {user_id}"
            )
            
            flash(f'User "{name}" updated successfully!', "success")
            return redirect(url_for("main.userList"))

        else: # GET request
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute("SELECT * FROM subadmin WHERE subadmin_id = %s", (user_id,))
                user = cursor.fetchone()
                if not user:
                    flash("User not found.", "danger")
                    return redirect(url_for("main.userList"))

                cursor.execute("SELECT r_id, role_name FROM subadminroles ORDER BY role_name ASC")
                all_roles = cursor.fetchall()
                
            return render_template("create_edit_user.html", user=user, all_roles=all_roles)

    except pymysql.err.IntegrityError:
        connection.rollback()
        flash("That email or username is already in use by another account.", "danger")
        return redirect(url_for("main.editUser", user_id=user_id))
    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"Error editing user {user_id}: {e}")
        flash("An error occurred while editing the user.", "danger")
        return redirect(url_for("main.userList"))
    finally:
        connection.close()



@main.route("/users/delete/<int:user_id>", methods=["POST"])
@adm_login_required
@subadmin_permission_required("USERS.delete_users")
def deleteUser(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT subadmin_username FROM subadmin WHERE subadmin_id = %s", (user_id,))
            subadmin = cursor.fetchone()
            
            cursor.execute("DELETE FROM subadmin WHERE subadmin_id = %s", (user_id,))
        connection.commit()
        
        if subadmin:
            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                "Delete",
                "Users/User Management",
                f"Deleted User '{subadmin['subadmin_username']}' with ID '{user_id}'",
            )
        
        flash("User has been deleted successfully.", "success")
        
    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"Error deleting user {user_id}: {e}")
        flash("An error occurred while deleting the user.", "danger")
    finally:
        connection.close()
    return redirect(url_for("main.userList"))


@main.route("/users/activities")
@adm_login_required
@subadmin_permission_required("USER_ACTIVITIES.view_user_activities")
def usersActivities():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    event_type = request.args.get('event_type')
    user_filter = request.args.get('user')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    connection = get_db_connection()
    activities = []
    total = 0
    event_types = []

    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            query = "SELECT * FROM user_activities"
            conditions = []
            params = []
            if event_type:
                conditions.append("event_type = %s")
                params.append(event_type)
            if user_filter:
                conditions.append("user_name LIKE %s")
                params.append(f"%{user_filter}%")
            if date_from:
                conditions.append("event_time >= %s")
                params.append(date_from)
            if date_to:
                conditions.append("event_time <= %s")
                params.append(f"{date_to} 23:59:59")

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            count_query = "SELECT COUNT(*) as total FROM (" + query + ") as filtered"
            cursor.execute(count_query, tuple(params))
            total = cursor.fetchone()['total']

            query += " ORDER BY id DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])

            cursor.execute(query, tuple(params))
            activities = cursor.fetchall()
            
            cursor.execute("SELECT DISTINCT event_type FROM user_activities ORDER BY event_type")
            event_types = [row['event_type'] for row in cursor.fetchall()]

    except Exception as e:
        current_app.logger.error(f"Error fetching user activities: {e}")
        flash("An error occurred while fetching user activities.", "danger")
    finally:
        connection.close()
    
    total_pages = (total + per_page - 1) // per_page
    page_items, last_page = [], 0
    for page_num in range(1, total_pages + 1):
        if page_num <= 2 or page_num > total_pages - 2 or abs(page_num - page) <= 2:
            if last_page + 1 != page_num:
                page_items.append(None)
            page_items.append(page_num)
            last_page = page_num

    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': total_pages,
        'has_prev': page > 1,
        'has_next': page * per_page < total,
        'prev_num': page - 1,
        'next_num': page + 1,
        'iter_pages': lambda: page_items
    }

    return render_template(
        'usersActivities.html',
        activities=activities,
        pagination=pagination,
        event_types=event_types,
        current_filters={
            'event_type': event_type,
            'user': user_filter,
            'date_from': date_from,
            'date_to': date_to
        }
    )

@main.route("/debug/permissions")
@adm_login_required
def debug_permissions():
    """Debug route to check current session permissions"""
    return jsonify(
        {
            "user_type": session.get("user_type"),
            "admin_id": session.get("admin_id"),
            "subadmin_id": session.get("subadmin_id"),
            "role_id": session.get("role_id"),
            "permissions": session.get("permissions"),
            "session_keys": list(session.keys()),
        }
    )


@main.route("/debug/force-reload-permissions")
@adm_login_required
def debug_force_reload_permissions():
    """Force reload permissions for debugging"""
    if "subadmin_id" in session:
        load_subadmin_permissions()
        flash("Permissions reloaded from database", "info")
    else:
        flash("Not a subadmin user", "warning")
    return redirect(url_for("main.admDashboard"))

