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


def get_s3_client():
    """
    Initializes and returns the Boto3 S3 client.
    It will automatically use the IAM Role when running on EC2.
    """
    return boto3.client("s3", region_name=current_app.config.get("AWS_REGION"))


def upload_file_to_s3(file_obj, bucket_name, object_name):
    """Uploads a file object to S3."""
    s3_client = get_s3_client()
    try:
        content_type = getattr(file_obj, "content_type", "application/octet-stream")

        s3_client.upload_fileobj(
            file_obj,
            bucket_name,
            object_name,
            ExtraArgs={
                "ContentType": content_type,
                "ContentDisposition": "inline",  # <-- THIS LINE IS ESSENTIAL
            },
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
                sql,
                (user_id, user_name, user_type, client_ip, event_type, model, value),
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
        return True  # Fail-safe
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


def _azure_analyze_file(client, model_id, file_path_or_bytes):
    """
    Calls Azure DI Read/Layout and returns the result object.
    """
    if isinstance(file_path_or_bytes, (bytes, bytearray)):
        poller = client.begin_analyze_document(
            model_id=model_id,
            body=file_path_or_bytes,  # Use 'body' as the new error requests
            content_type="application/pdf",
        )
    else:
        with open(file_path_or_bytes, "rb") as f:
            poller = client.begin_analyze_document(
                model_id=model_id,
                body=f,  # Use 'body' as the new error requests
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
            result = _azure_analyze_file(client, model_id, filepath)

            full_text = []
            for page in result.pages:
                full_text.append(f"--- Page {page.page_number} ---")
                for line in page.lines:
                    full_text.append(line.content)
                full_text.append("")

            return "\n".join(full_text)

        except (HttpResponseError, ServiceResponseError, ServiceRequestError) as e:
            last_exception = e
            current_app.logger.warning(
                f"[Azure OCR] Retriable API error on attempt {attempt + 1}/{max_retries}. Error: {e}"
            )
        except Exception as e:
            current_app.logger.error(
                f"[Azure OCR] Unexpected, non-retriable error during analysis: {e}"
            )
            raise ConnectionError(
                f"An unexpected error occurred during Azure analysis: {e}"
            )

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

# Task ----
# 1.⁠ ⁠total documents uploaded +
# 2.⁠ ⁠Total characters/tokens extracted +
# 3.⁠ ⁠Total space used +
# 4.⁠ ⁠Total users +
# 5.⁠ ⁠Total Token extracted from azure +
# 6.⁠ ⁠Total Token extracted from tesseract +
# 7.⁠ ⁠Total pages scanned +
# 8.⁠ ⁠Total pages scanned by azure +
# 9.⁠ ⁠Total pages scanned by tesseract +
# 10. total admin +
# 11. total subadmin  +
# 12. total categories  +
# 13. total subCategories  +
# 14. total tags +


def format_bytes(size):
    """Converts bytes to a human-readable format (KB, MB, GB)."""
    if size is None:
        return "N/A"
    power = 1024
    n = 0
    power_labels = {0: "", 1: "K", 2: "M", 3: "G", 4: "T"}
    while size >= power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"


def get_s3_bucket_size():
    """
    Calculates the total bucket size by iterating through all objects in real-time.
    WARNING: This can be VERY SLOW for buckets with many files.
    """
    try:
        s3 = get_s3_client()
        bucket_name = current_app.config.get("AWS_S3_BUCKET")
        total_size = 0
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket_name)

        for page in pages:
            for obj in page.get("Contents", []):
                total_size += obj["Size"]
        return format_bytes(total_size)

    except Exception as e:
        current_app.logger.error(f"Could not get S3 bucket size by iterating: {e}")
        return "Error"


def get_dashboard_stats():
    """Fetches various statistics for the dashboard from the database."""
    stats = {
        "upload": 0,
        "admin": 0,
        "subadmin": 0,
        "categories": 0,
        "subcategories": 0,
        "tags": 0,
        "tesseract_count": 0,
        "azure_count": 0,
        "total_tokens": 0,
        "tesseract_tokens": 0,
        "azure_tokens": 0,
        "s3_size": "0 B",
    }
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS count FROM documents")
            stats["upload"] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM admin")
            stats["admin"] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM subadmin")
            stats["subadmin"] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM categories")
            stats["categories"] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM sub_categories")
            stats["subcategories"] = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM tags")
            stats["tags"] = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) AS count FROM documents WHERE ocr_engine = 'tesseract'"
            )
            stats["tesseract_count"] = cursor.fetchone()["count"]

            cursor.execute(
                "SELECT COUNT(*) AS count FROM documents WHERE ocr_engine = 'azure'"
            )
            stats["azure_count"] = cursor.fetchone()["count"]

            cursor.execute("SELECT SUM(IFNULL(token_count, 0)) AS count FROM documents")
            stats["total_tokens"] = cursor.fetchone()["count"] or 0

            cursor.execute(
                "SELECT SUM(IFNULL(token_count, 0)) AS count FROM documents WHERE ocr_engine = 'tesseract'"
            )
            stats["tesseract_tokens"] = cursor.fetchone()["count"] or 0

            cursor.execute(
                "SELECT SUM(IFNULL(token_count, 0)) AS count FROM documents WHERE ocr_engine = 'azure'"
            )
            stats["azure_tokens"] = cursor.fetchone()["count"] or 0

    except Exception as e:
        current_app.logger.error(f"Error fetching dashboard stats: {e}")
    finally:
        if connection:
            connection.close()
    stats["s3_size"] = get_s3_bucket_size()

    return stats


# ---------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------


def log_super_admin_activity(superadmin_id, event_type, model, value):
    connection = get_db_connection()
    try:
        superadmin_ip = get_client_ip()
        with connection.cursor() as cursor:
            sql = """
            INSERT INTO super_admin_activities
            (superadmin_id, superadmin_ip, event_type, model, value)
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(
                sql, (superadmin_id, superadmin_ip, event_type, model, value)
            )
        connection.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log super admin activity: {e}")
        connection.rollback()
    finally:
        if connection:
            connection.close()

def log_admin_subadmin_activity(admin_subadmin_mail, event_type, model, value):
    connection = get_db_connection()
    try:
        admin_subadmin_ip = get_client_ip()
        with connection.cursor() as cursor:
            sql = """
            INSERT INTO admin_subadmin_activities
            (admin_id, admin_ip, event_type, model, value)
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(
                sql, (admin_subadmin_mail, admin_subadmin_ip, event_type, model, value)
            )
        connection.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log super admin activity: {e}")
        connection.rollback()
    finally:
        if connection:
            connection.close()


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
            if "admin_id" in session:
                return f(*args, **kwargs)
            if "subadmin_id" in session:
                if "permissions" not in session:
                    load_subadmin_permissions()
                if "permissions" in session and session["permissions"]:
                    try:
                        module, action = permission_key.split(".")

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
                return render_template("accessdenied.html"), 403

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
                cursor.execute(
                    "SELECT * FROM superadmin WHERE superadmin_email=%s", (email.data,)
                )
                if cursor.fetchone():
                    raise ValidationError(
                        "Email already exist in super admin portal . Please choose another."
                    )

                cursor.execute(
                    "SELECT * FROM admin WHERE admin_email=%s", (email.data,)
                )
                if cursor.fetchone():
                    raise ValidationError(
                        "Email already exist in admin portal. Please choose another."
                    )
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

                cursor.execute(
                    "SELECT * FROM superadmin WHERE superadmin_email=%s", (email.data,)
                )
                if cursor.fetchone():
                    raise ValidationError(
                        "Email already exist in super admin portal . Please choose another."
                    )

                cursor.execute(
                    "SELECT * FROM admin WHERE admin_email=%s", (email.data,)
                )
                if cursor.fetchone():
                    raise ValidationError(
                        "Email already exist in admin portal. Please choose another."
                    )
        finally:
            connection.close()


# ---------------------------------------------------------------------
# Authentication Routes -> Super Admin Authentication -> Routes
# ---------------------------------------------------------------------


@main.route("/superadmin/supadmregistration", methods=["GET", "POST"])
def supAdmRegistration():
    if does_superadmin_exist():
        flash(
            "Registration is disabled. Only one superadmin account is allowed.",
            "warning",
        )
        return redirect(url_for("main.admLogin"))

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
                    (form.name.data, form.email.data, hashed_password),
                )
                connection.commit()

            # Get the ID of the user that was just created
            new_superadmin_id = cursor.lastrowid

            connection.commit()

            log_super_admin_activity(
                new_superadmin_id,
                "Authentication",
                "Registration",
                f"First Super Admin '{form.name.data}' registered successfully.",
            )

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("main.admLogin"))

        except Exception as e:
            if connection:
                connection.rollback()
            flash(f"Error during registration: {str(e)}", "danger")
        finally:
            if connection:
                connection.close()

    return render_template("supAdmRegistration.html", form=form)


@main.route("/superadmin/supadmdashboard")
@sup_adm_login_required
def supAdmDashboard():
    try:
        log_super_admin_activity(
            session["sup_adm_id"],
            "View",
            "Super Admin Dashboard",
            "Accessed the main dashboard.",
        )
    except Exception as e:
        current_app.logger.error(f"Error : {e}")
    return render_template("supAdmDashboard.html")


@main.route("/superadmin/supadmlogout")
@sup_adm_login_required
def supAdmLogout():
    try:
        user_name = session.get("sup_adm_name", "Unknown Super Admin")
        log_super_admin_activity(
            session["sup_adm_id"],
            "Logout",
            "Authentication",
            f"Super Admin '{user_name}' logged out successfully.",
        )
    except Exception as e:
        current_app.logger.error(f"Error logging super admin logout: {e}")

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
                "SELECT * FROM superadmin WHERE superadmin_id = %s",
                (session["sup_adm_id"],),
            )
            superadmin = cursor.fetchone()
            try:
                log_super_admin_activity(
                    session["sup_adm_id"],
                    "View",
                    "Super Admin Profile",
                    "Accessed their own profile page.",
                )
            except Exception as log_error:
                current_app.logger.error(
                    f"Failed to log profile view activity: {log_error}"
                )

            print(f"Fetched user: {superadmin}")
            return render_template("supAdmProfile.html", superadmin=superadmin)
    except Exception as e:
        current_app.logger.error(f"Error fetching superadmin profile: {e}")
        flash("An error occurred while fetching your profile.", "danger")
        return redirect(url_for("main.supAdmlogin"))
    finally:
        connection.close()


# @main.route("/superadmin/supadmcreateadmin", methods=["GET", "POST"])
# @sup_adm_login_required
# def supAdmCreateAdmin():
#     form = admRegisterForm()
#     if form.validate_on_submit():
#         hashed_password = bcrypt.hashpw(
#             form.password.data.encode("utf-8"), bcrypt.gensalt()
#         ).decode("utf-8")

#         connection = get_db_connection()
#         try:
#             with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#                 cursor.execute(
#                     "INSERT INTO admin (admin_name, admin_email, admin_password, superadmin_id) VALUES (%s, %s, %s, %s)",
#                     (
#                         form.name.data,
#                         form.email.data,
#                         hashed_password,
#                         session["sup_adm_id"],
#                     ),
#                 )
#                 connection.commit()
#                 flash("New Admin Created successfully", "success")

#                 cursor.execute(
#                     "SELECT * FROM admin WHERE admin_email = %s", (form.email.data,)
#                 )
#                 admin = cursor.fetchone()
#                 try:
#                    log_super_admin_activity(
#                     session["sup_adm_id"],
#                     "Create",
#                     "Super Admin Create",
#                     "Super admin creatred admin '{form.name.data}'"
#                   )
#                except Exception as log_error:
#                      current_app.logger.error(f"Failed to log profile view activity: {log_error}")
#         except Exception as e:
#             connection.rollback()
#             flash(f"Error creating admin: {e}", "danger")
#         finally:
#             connection.close()

#     connection = get_db_connection()
#     adminlist = []
#     try:
#         with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#             query = """
#                 SELECT a.admin_id, a.admin_name, a.admin_email, a.created_at, s.superadmin_id, s.superadmin_name
#                 FROM admin AS a
#                 INNER JOIN superadmin AS s ON a.superadmin_id = s.superadmin_id
#                 ORDER BY a.admin_id ASC
#             """
#             cursor.execute(query)
#             adminlist = cursor.fetchall()
#     except Exception as e:
#         current_app.logger.error(f"Error fetching admin list: {e}")
#         flash("An error occurred while fetching admin list.", "danger")
#     finally:
#         connection.close()

#     return render_template("supAdmAdmin.html", form=form, adminlist=adminlist)

# # In routes.py


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
                new_admin_id = cursor.lastrowid
                connection.commit()
                flash("New Admin created successfully!", "success")
                try:
                    log_super_admin_activity(
                        session["sup_adm_id"],
                        "Create",
                        "Admin Management",
                        f"Created new admin '{form.name.data}' with ID: {new_admin_id}.",
                    )
                except Exception as log_error:

                    current_app.logger.error(
                        f"Failed to log admin creation activity: {log_error}"
                    )

        except Exception as e:
            if connection:
                connection.rollback()
            flash(f"Error creating admin: {e}", "danger")
        finally:
            if connection:
                connection.close()
        return redirect(url_for("main.supAdmCreateAdmin"))
    connection = get_db_connection()
    adminlist = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            query = """
                SELECT a.admin_id, a.admin_name, a.admin_email, a.created_at, s.superadmin_name, s.superadmin_id
                FROM admin AS a
                INNER JOIN superadmin AS s ON a.superadmin_id = s.superadmin_id
                ORDER BY a.admin_id ASC
            """
            cursor.execute(query)
            adminlist = cursor.fetchall()
    except Exception as e:
        current_app.logger.error(f"Error fetching admin list: {e}")
        flash("An error occurred while fetching the admin list.", "danger")
    finally:
        if connection:
            connection.close()

    return render_template("supAdmAdmin.html", form=form, adminlist=adminlist)


# @main.route("/superadmin/supadmactivities")
# @sup_adm_login_required
# def supAdmActivities():
#     page = request.args.get("page", 1, type=int)
#     per_page = 20
#     event_type = request.args.get("event_type")
#     admin_filter = request.args.get("admin")
#     date_from = request.args.get("date_from")
#     date_to = request.args.get("date_to")

#     connection = get_db_connection()
#     activities = []
#     total = 0
#     event_types = []

#     try:
#         with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#             query = "SELECT * FROM user_activities WHERE user_type = 'Super Admin'"

#             conditions = []
#             params = []

#             if event_type:
#                 conditions.append("event_type = %s")
#                 params.append(event_type)

#             if admin_filter:
#                 conditions.append("user_name LIKE %s")
#                 params.append(f"%{admin_filter}%")

#             if date_from:
#                 conditions.append("event_time >= %s")
#                 params.append(date_from)

#             if date_to:
#                 conditions.append("event_time <= %s")
#                 params.append(f"{date_to} 23:59:59")
#             if conditions:
#                 query += " AND " + " AND ".join(conditions)

#             count_query = f"SELECT COUNT(*) as total FROM ({query}) as filtered"

#             cursor.execute(count_query, tuple(params))
#             total_result = cursor.fetchone()
#             total = total_result['total'] if total_result else 0


#             query += " ORDER BY id DESC LIMIT %s OFFSET %s"
#             params.extend([per_page, (page - 1) * per_page])
#             cursor.execute(query, tuple(params))
#             activities = cursor.fetchall()

#             cursor.execute(
#                 "SELECT DISTINCT event_type FROM user_activities WHERE user_type = 'Super Admin' ORDER BY event_type"
#             )
#             event_types = [row["event_type"] for row in cursor.fetchall()]

#     except Exception as e:
#         current_app.logger.error(f"Error fetching superadmin activities: {e}")
#         flash("An error occurred while fetching activities.", "danger")
#     finally:
#         connection.close()

#     total_pages = (total + per_page - 1) // per_page if total > 0 else 0
#     page_items, last_page = [], 0
#     for page_num in range(1, total_pages + 1):
#         if page_num <= 2 or page_num > total_pages - 2 or abs(page_num - page) <= 2:
#             if last_page + 1 != page_num:
#                 page_items.append(None)
#             page_items.append(page_num)
#             last_page = page_num

#     pagination = {
#         "page": page,
#         "per_page": per_page,
#         "total": total,
#         "pages": total_pages,
#         "has_prev": page > 1,
#         "has_next": page < total_pages,
#         "prev_num": page - 1,
#         "next_num": page + 1,
#         "iter_pages": lambda: page_items,
#     }

#     return render_template(
#         "supAdmActivities.html",
#         activities=activities,
#         pagination=pagination,
#         event_types=event_types,
#         current_filters={
#             "event_type": event_type,
#             "admin": admin_filter,
#             "date_from": date_from,
#             "date_to": date_to,
#         },
#     )

# main.route("/superadmin/supadmactivities")
# @sup_adm_login_required
# def supAdmActivities():
#     page = request.args.get("page", 1, type=int)
#     per_page = 20
#     event_type = request.args.get("event_type")
#     admin_filter = request.args.get("admin") # This will filter by superadmin_name
#     date_from = request.args.get("date_from")
#     date_to = request.args.get("date_to")

#     connection = get_db_connection()
#     activities = []
#     total = 0
#     event_types = []

#     try:
#         with connection.cursor(pymysql.cursors.DictCursor) as cursor:
#             # --- START: CORE FIX ---
#             # Base query now JOINS the two tables to get the superadmin_name
#             base_query = """
#                 FROM super_admin_activities AS act
#                 JOIN superadmin AS s ON act.superadmin_id = s.superadmin_id
#             """

#             conditions = []
#             params = []

#             if event_type:
#                 conditions.append("act.event_type = %s")
#                 params.append(event_type)

#             if admin_filter:
#                 # Correctly filter by the name from the 'superadmin' table
#                 conditions.append("s.superadmin_name LIKE %s")
#                 params.append(f"%{admin_filter}%")

#             if date_from:
#                 conditions.append("act.event_time >= %s")
#                 params.append(date_from)

#             if date_to:
#                 # Add time component to include the entire end day
#                 conditions.append("act.event_time <= %s")
#                 params.append(f"{date_to} 23:59:59")

#             where_clause = ""
#             if conditions:
#                 where_clause = "WHERE " + " AND ".join(conditions)

#             # Build and execute the count query first for correct pagination
#             count_query = f"SELECT COUNT(act.id) as total {base_query} {where_clause}"
#             cursor.execute(count_query, tuple(params))
#             total_result = cursor.fetchone()
#             total = total_result['total'] if total_result else 0

#             # Build the main data query with all columns needed for the template
#             select_columns = """
#                 SELECT
#                     act.id, act.event_time, act.event_type, act.model,
#                     act.value, act.superadmin_ip, s.superadmin_name
#             """
#             main_query = f"{select_columns} {base_query} {where_clause} ORDER BY act.id DESC LIMIT %s OFFSET %s"

#             # Add pagination parameters and execute
#             final_params = list(params) # Create a copy of the params for the main query
#             final_params.extend([per_page, (page - 1) * per_page])
#             cursor.execute(main_query, tuple(final_params))
#             activities = cursor.fetchall()

#             # Get distinct event types from the correct table
#             cursor.execute("SELECT DISTINCT event_type FROM super_admin_activities ORDER BY event_type")
#             event_types = [row["event_type"] for row in cursor.fetchall()]
#             # --- END: CORE FIX ---

#     except Exception as e:
#         current_app.logger.error(f"Error fetching superadmin activities: {e}")
#         flash("An error occurred while fetching activities.", "danger")
#     finally:
#         if connection:
#             connection.close()

#     # --- Pagination and Rendering (no changes needed here) ---
#     total_pages = (total + per_page - 1) // per_page if total > 0 else 0
#     page_items, last_page = [], 0
#     for page_num in range(1, total_pages + 1):
#         if page_num <= 2 or page_num > total_pages - 2 or abs(page_num - page) <= 2:
#             if last_page + 1 != page_num:
#                 page_items.append(None)
#             page_items.append(page_num)
#             last_page = page_num

#     pagination = {
#         "page": page, "per_page": per_page, "total": total, "pages": total_pages,
#         "has_prev": page > 1, "has_next": page < total_pages,
#         "prev_num": page - 1, "next_num": page + 1, "iter_pages": lambda: page_items,
#     }

#     return render_template(
#         "supAdmActivities.html",
#         activities=activities,
#         pagination=pagination,
#         event_types=event_types,
#         current_filters={
#             "event_type": event_type,
#             "admin": admin_filter,
#             "date_from": date_from,
#             "date_to": date_to,
#         },
#     )


@main.route("/superadmin/supadmactivities")
@sup_adm_login_required
def supAdmActivities():
    page = request.args.get("page", 1, type=int)
    per_page = 20
    event_type = request.args.get("event_type")
    admin_filter = request.args.get("admin")  # This will filter by superadmin_name
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")

    connection = get_db_connection()
    activities = []
    total = 0
    event_types = []

    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            # --- START: CORE FIX ---
            # Base query now JOINS the two tables to get the superadmin_name
            base_query = """
                FROM super_admin_activities AS act
                JOIN superadmin AS s ON act.superadmin_id = s.superadmin_id
            """

            conditions = []
            params = []

            if event_type:
                conditions.append("act.event_type = %s")
                params.append(event_type)

            if admin_filter:
                # Correctly filter by the name from the 'superadmin' table
                conditions.append("s.superadmin_name LIKE %s")
                params.append(f"%{admin_filter}%")

            if date_from:
                conditions.append("act.event_time >= %s")
                params.append(date_from)

            if date_to:
                # Add time component to include the entire end day
                conditions.append("act.event_time <= %s")
                params.append(f"{date_to} 23:59:59")

            where_clause = ""
            if conditions:
                where_clause = "WHERE " + " AND ".join(conditions)

            # Build and execute the count query first for correct pagination
            count_query = f"SELECT COUNT(act.id) as total {base_query} {where_clause}"
            cursor.execute(count_query, tuple(params))
            total_result = cursor.fetchone()
            total = total_result["total"] if total_result else 0

            # Build the main data query with all columns needed for the template
            select_columns = """
                SELECT 
                    act.id, act.event_time, act.event_type, act.model, 
                    act.value, act.superadmin_ip, s.superadmin_name
            """
            main_query = f"{select_columns} {base_query} {where_clause} ORDER BY act.id DESC LIMIT %s OFFSET %s"

            # Add pagination parameters and execute
            final_params = list(
                params
            )  # Create a copy of the params for the main query
            final_params.extend([per_page, (page - 1) * per_page])
            cursor.execute(main_query, tuple(final_params))
            activities = cursor.fetchall()

            # Get distinct event types from the correct table
            cursor.execute(
                "SELECT DISTINCT event_type FROM super_admin_activities ORDER BY event_type"
            )
            event_types = [row["event_type"] for row in cursor.fetchall()]
            # --- END: CORE FIX ---

    except Exception as e:
        current_app.logger.error(f"Error fetching superadmin activities: {e}")
        flash("An error occurred while fetching activities.", "danger")
    finally:
        if connection:
            connection.close()

    if not request.args:
        try:
            user_name = session.get("sup_adm_name", "Unknown Super Admin")
            log_super_admin_activity(
                session["sup_adm_id"],
                "View",
                "Super Admin Activities", 
                f"Super Admin '{user_name}' viewed the activities list." 
            )
        except Exception as e:
            current_app.logger.error(f"Error logging activity view: {e}")

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
                cursor.execute(
                    "SELECT * FROM superadmin WHERE superadmin_email=%s",
                    (form.email.data,),
                )
                superadmin = cursor.fetchone()

                if superadmin:
                    if superadmin and bcrypt.checkpw(
                        form.password.data.encode("utf-8"),
                        superadmin["superadmin_password"].encode("utf-8"),
                    ):
                        session["sup_adm_id"] = superadmin["superadmin_id"]
                        session["sup_adm_name"] = superadmin["superadmin_name"]
                        session["sup_adm_mail"] = superadmin["superadmin_email"]

                        user_name = session.get("sup_adm_name", "Unknown Super Admin")
                        log_super_admin_activity(
                            session["sup_adm_id"],
                            "Authentication",
                            "Super Admin Management",
                            f"Super admin '{user_name}' Login.",
                        )
                    return redirect(url_for("main.supAdmDashboard"))

                # checking if it's an admin
                cursor.execute(
                    "SELECT * FROM admin WHERE admin_email=%s", (form.email.data,)
                )
                user = cursor.fetchone()

                if user:
                    if bcrypt.checkpw(
                        form.password.data.encode("utf-8"),
                        user["admin_password"].encode("utf-8"),
                    ):
                        session["admin_id"] = user["admin_id"]
                        session["admin_name"] = user["admin_name"]
                        session["admin_mail"] = user["admin_email"]
                        session["user_type"] = "admin"

                        user_name2 = session.get("admin_name", "Unknown Admin")
                        log_admin_subadmin_activity(
                            session["admin_mail"],
                            "Authentication",
                            "Admin Management",
                            f"Admin '{user_name2}' Login.",
                        )
                        return redirect(url_for("main.admDashboard"))

                cursor.execute(
                    "SELECT * FROM subadmin WHERE subadmin_email=%s", (form.email.data,)
                )
                subadmin_user = cursor.fetchone()

                if subadmin_user:
                    password_hash = subadmin_user.get("subadmin_password")
                    if password_hash and bcrypt.checkpw(
                        form.password.data.encode("utf-8"),
                        password_hash.encode("utf-8"),
                    ):
                        session["subadmin_id"] = subadmin_user["subadmin_id"]
                        session["subadmin_name"] = subadmin_user["subadmin_name"]
                        session["subadmin_email"] = subadmin_user["subadmin_email"]
                        session["subadmin_username"] = subadmin_user["subadmin_username"]
                        session["role_id"] = subadmin_user["role_id"]
                        session["user_type"] = "subadmin"

                        load_subadmin_permissions()
                        user_name3 = session.get("subadmin_name", "Unknown Admin")
                        log_admin_subadmin_activity(
                            session["subadmin_email"],
                            "Authentication",
                            "Admin Management",
                            f"Sub Admin '{user_name3}' Login.",
                        )

                        # log_user_activity(
                        #     subadmin_user["subadmin_id"],
                        #     subadmin_user["subadmin_name"],
                        #     "Subadmin",
                        #     "Login",
                        #     "Landing Page/Login",
                        #     f"Subadmin logged in, Id: {subadmin_user['subadmin_id']}, Name: {subadmin_user['subadmin_name']}",
                        # )
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
    try:
        user_name = session.get("admin_name","subadmin_name", "Unknown Admin")
        log_admin_subadmin_activity(
            session["admin_mail"] or session.get("subadmin_email"),
            "View",
            "Admin Or Sub Admin Dashboard",
            f"{user_name} accessed the main dashboard.",
        )

        # log_admin_activity(
        #     session["admin_id"],
        #     "View",
        #     "Admin Dashboard",
        #     "Accessed the main dashboard.",
        # )
    except Exception as e:
        current_app.logger.error(f"Error : {e}")

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
                cursor.execute(
                    "SELECT * FROM admin WHERE admin_id = %s", (session["admin_id"],)
                )
            elif "subadmin_id" in session:
                cursor.execute(
                    "SELECT * FROM subadmin WHERE subadmin_id = %s",
                    (session["subadmin_id"],),
                )

            user = cursor.fetchone()
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for("main.admLogin"))

            return render_template(
                "admProfile.html", user=user, user_type=session.get("user_type")
            )
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

            user_name = session.get("admin_name","subadmin_name", "Unknown Admin")
            log_admin_subadmin_activity(
                session["admin_mail"] or session.get("subadmin_email"),
                "View",
                "Categories Page",
                f"{user_name} accessed the Categories Page.",
            )
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

        user_name = session.get("admin_name","subadmin_name", "Unknown Admin")
        log_admin_subadmin_activity(
                session["admin_mail"] or session.get("subadmin_email"),
                "Create",
                "Categories Page",
                f"{user_name} created New Category Called '{category_name}'",
            )
        # log_user_activity(
        #     session.get("admin_id") or session.get("subadmin_id"),
        #     session.get("admin_name") or session.get("subadmin_name"),
        #     session.get("user_type"),
        #     "Create",
        #     "App/Master Entries/Categories",
        #     f"Created New Category Called '{category_name}'",
        # )

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

            user_name = session.get("admin_name","subadmin_name", "Unknown Admin")
            log_admin_subadmin_activity(
                session["admin_mail"] or session.get("subadmin_email"),
                "Edit",
                "Categories Page",
                f"{user_name} edited Category '{new_name}' with Category ID = '{cat_id}'",
            )

            # log_user_activity(
            #     session.get("admin_id") or session.get("subadmin_id"),
            #     session.get("admin_name") or session.get("subadmin_name"),
            #     session.get("user_type"),
            #     "Edit",
            #     "App/Master Entries/Categories",
            #     f"Edited Category '{new_name}' with Category ID = '{cat_id}'",
            # )

            flash("Category updated successfully!", "success")
        else:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "SELECT c_id, category_name FROM categories WHERE c_id = %s",
                    (cat_id,),
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
                user_name = session.get("admin_name","subadmin_name", "Unknown Admin")
                log_admin_subadmin_activity(
                    session["admin_mail"] or session.get("subadmin_email"),
                    "Edit",
                    "Categories Page",
                    f"{user_name} deleted Category '{category['category_name']}' with Category ID '{cate_id}''",
                )
                # log_user_activity(
                #     session.get("admin_id") or session.get("subadmin_id"),
                #     session.get("admin_name") or session.get("subadmin_name"),
                #     session.get("user_type"),
                #     "Delete",
                #     "App/Master Entries/Categories",
                #     f"Deleted Category '{category['category_name']}' with Category ID '{cate_id}'",
                # )

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
            cursor.execute(
                "SELECT c_id , category_name FROM categories ORDER BY c_id ASC"
            )
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
            category_name = (
                category_data["category_name"] if category_data else "Unknown"
            )

            cursor.execute(
                "INSERT INTO sub_categories (category_id, sub_category_name) VALUES (%s, %s)",
                (category_id, sub_category_name),
            )
        connection.commit()

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            "Create",
            "App/Master Entries/Sub Categories",
            f"Created New Sub Category Called '{sub_category_name}' with Category name '{category_name}' Category ID '{category_id}'",
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
                    "SELECT sub_category_name FROM sub_categories WHERE sc_id = %s",
                    (sub_cat_id,),
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
                    "Edit",
                    "App/Master Entries/Sub Categories",
                    f"Edited Sub category from '{old_sub_cat['sub_category_name']}' to '{new_name}' with Sub Category ID = '{sub_cat_id}'",
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

                cursor.execute(
                    "DELETE FROM sub_categories WHERE sc_id = %s", (sub_cat_id,)
                )
            connection.commit()

            if sub_category:
                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    "Delete",
                    "App/Master Entries/Sub Categories",
                    f"Deleted Sub Category '{sub_category['sub_category_name']}' with Sub Category ID '{sub_cat_id}'",
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
            "Create",
            "App/Master Entries/Tags",
            f"Created New Tag Called '{tag_name}'",
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
                cursor.execute("SELECT tag_name FROM tags WHERE t_id = %s", (tag_id,))
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
                    "Edit",
                    "App/Master Entries/Tags",
                    f"Edited Tag from '{old_tag['tag_name']}' to '{new_name}' where Tag ID = '{tag_id}'",
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
                    "Delete",
                    "App/Master Entries/Tags",
                    f"Deleted Tag '{tag['tag_name']}' with Tag ID '{tag_id}'",
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


@main.route("/documents/add-new", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("DOCUMENTS.create_document")
def addNewDocuments():
    """
    Handles the initial form submission for document analysis.
    Performs OCR and AI analysis and returns the extracted data to the client.
    """
    if request.method == "POST":
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
                filepath = os.path.join(
                    current_app.config["UPLOAD_FOLDER"], unique_filename
                )
                file.save(filepath)

                form_data_dict = form_data.to_dict()

                tags_list = form_data.getlist("tags")

                form_data_dict["tags"] = tags_list

                session["processing_filepath"] = filepath
                session["original_filename"] = original_filename
                session["unique_filename_for_s3"] = unique_filename
                session["form_data_for_submission"] = form_data_dict

                ocr_engine = form_data.get("ocr_engine", "azure")
                session["form_data_for_submission"]["ocr_engine"] = ocr_engine

                raw_text = ""
                if ocr_engine == "tesseract":
                    mime_type = magic.from_file(filepath, mime=True)
                    raw_text = perform_tesseract_ocr(filepath, mime_type)
                else:
                    raw_text = perform_azure_ocr(filepath)

                if not raw_text.strip():
                    os.remove(filepath)
                    session.pop("processing_filepath", None)
                    return (
                        jsonify(
                            {
                                "error": "OCR failed to extract any text from the document."
                            }
                        ),
                        400,
                    )

                token_count = len(raw_text.split())
                session["form_data_for_submission"]["token_count"] = token_count

                log_user_activity(
                    session.get("admin_id") or session.get("subadmin_id"),
                    session.get("admin_name") or session.get("subadmin_name"),
                    session.get("user_type"),
                    "File Upload",
                    "Documents/Add New",
                    f"Uploaded document '{original_filename}' for analysis.",
                )

                analysis_result = analyze_document_with_openai(raw_text)
                return jsonify(
                    {
                        "message": "Document analyzed successfully. Please review and save.",
                        "extracted_data": analysis_result,
                    }
                )
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
            return (
                jsonify(
                    {"error": "An internal error occurred. Please try again later."}
                ),
                500,
            )

    connection = get_db_connection()
    all_categories = []
    all_subcategories = []
    all_tags = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT category_name FROM categories ORDER BY category_name ASC"
            )
            all_categories = cursor.fetchall()
            cursor.execute(
                "SELECT sub_category_name FROM sub_categories ORDER BY sub_category_name ASC"
            )
            all_subcategories = cursor.fetchall()
            cursor.execute("SELECT t_id, tag_name FROM tags ORDER BY tag_name ASC")
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
        tags=all_tags,
    )


@main.route("/documents/submit", methods=["POST"])
@adm_login_required
def submitDocument():
    """
    Handles the final submission after the user has reviewed and edited the extracted data.
    Saves the document and links multiple tags.
    """
    filepath = session.get("processing_filepath")
    form_data = session.get("form_data_for_submission")
    original_filename = session.get("original_filename")
    unique_filename_for_s3 = session.get("unique_filename_for_s3")

    if not all([filepath, form_data, original_filename, unique_filename_for_s3]):
        return (
            jsonify(
                {"error": "Analysis data not found. Please re-analyze the document."}
            ),
            400,
        )

    edited_data_json_str = request.form.get("extracted_data")
    if not edited_data_json_str:
        return jsonify({"error": "No extracted data provided for submission."}), 400

    tags_list = form_data.get("tags", [])

    try:
        json.loads(edited_data_json_str)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format in the extracted data."}), 400

    connection = get_db_connection()
    try:
        file_url = None
        with open(filepath, "rb") as f:
            file_url = upload_file_to_s3(
                f, current_app.config.get("AWS_S3_BUCKET"), unique_filename_for_s3
            )

        if not file_url:
            raise Exception("Failed to upload file to S3.")

        with connection.cursor() as cursor:
            # --- MODIFIED: The 'tags' column has been removed from the INSERT statement ---
            sql = """
                INSERT INTO documents (title, category, sub_category, file_path, 
                                       extracted_data, ocr_engine, token_count, original_filename)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            params = (
                form_data.get("title"),
                form_data.get("category"),
                form_data.get("sub_category"),
                file_url,
                edited_data_json_str,
                form_data.get("ocr_engine"),
                form_data.get("token_count", 0),
                original_filename,
            )
            cursor.execute(sql, params)

            new_document_id = cursor.lastrowid

            if tags_list and new_document_id:
                placeholders = ",".join(["%s"] * len(tags_list))
                sql_find_tags = (
                    f"SELECT t_id FROM tags WHERE tag_name IN ({placeholders})"
                )

                cursor.execute(sql_find_tags, tags_list)
                tag_ids = [row["t_id"] for row in cursor.fetchall()]

                if tag_ids:
                    sql_link_tags = "INSERT INTO document_tags (document_id, tag_id) VALUES (%s, %s)"
                    link_params = [(new_document_id, tag_id) for tag_id in tag_ids]
                    cursor.executemany(sql_link_tags, link_params)

        connection.commit()

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            "Create",
            "Documents/Submit",
            f"Saved new document '{form_data.get('title')}' with S3 URL: {file_url}",
        )

        return jsonify({"message": "Document and extracted data saved successfully!"})

    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"An unexpected error occurred during submission: {e}")
        return (
            jsonify(
                {"error": f"An internal error occurred during submission: {str(e)}"}
            ),
            500,
        )
    finally:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        session.pop("processing_filepath", None)
        session.pop("form_data_for_submission", None)
        session.pop("original_filename", None)
        session.pop("unique_filename_for_s3", None)
        connection.close()


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

            cursor.execute(
                "SELECT DISTINCT category FROM documents WHERE category IS NOT NULL AND category != '' ORDER BY category"
            )
            distinct_categories = [row["category"] for row in cursor.fetchall()]

            cursor.execute(
                "SELECT DISTINCT sub_category FROM documents WHERE sub_category IS NOT NULL AND sub_category != '' ORDER BY sub_category"
            )
            distinct_sub_categories = [row["sub_category"] for row in cursor.fetchall()]

            cursor.execute("SELECT tag_name FROM tags ORDER BY tag_name ASC")
            distinct_tags = [row["tag_name"] for row in cursor.fetchall()]

    except Exception as e:
        current_app.logger.error(f"Error fetching filter options: {e}")
        flash("An error occurred while fetching filter options.", "danger")
    finally:
        if connection:
            connection.close()

    return render_template(
        "documentsList.html",
        documents=[],
        distinct_categories=distinct_categories,
        distinct_sub_categories=distinct_sub_categories,
        distinct_tags=distinct_tags,
    )


@main.route("/api/search-documents")
@adm_login_required
def api_search_documents():
    """API endpoint to fetch and filter documents with multi-tag support, returns JSON."""
    search_query = request.args.get("search", "")
    category_filter = request.args.get("category", "")
    sub_category_filter = request.args.get("sub_category", "")
    tags_filter = request.args.get("tags", "")

    connection = get_db_connection()
    documents = []
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            base_sql = """
                SELECT 
                    d.id, d.title, d.category, d.sub_category, d.file_path,
                    d.created_at, d.original_filename,
                    GROUP_CONCAT(t.tag_name SEPARATOR ', ') as tags
                FROM documents d
                LEFT JOIN document_tags dt ON d.id = dt.document_id
                LEFT JOIN tags t ON dt.tag_id = t.t_id
            """

            conditions, params = [], []

            if search_query:
                search_like = f"%{search_query}%"

                conditions.append(
                    "(d.title LIKE %s OR CAST(d.extracted_data AS CHAR) LIKE %s OR d.original_filename LIKE %s)"
                )
                params.extend([search_like, search_like, search_like])

            if category_filter:
                conditions.append("d.category = %s")
                params.append(category_filter)
            if sub_category_filter:
                conditions.append("d.sub_category = %s")
                params.append(sub_category_filter)

            if conditions:
                base_sql += " WHERE " + " AND ".join(conditions)

            base_sql += " GROUP BY d.id"

            if tags_filter:

                base_sql += " HAVING tags LIKE %s"
                params.append(f"%{tags_filter}%")

            base_sql += " ORDER BY d.created_at DESC"

            cursor.execute(base_sql, tuple(params))
            documents = cursor.fetchall()

            for doc in documents:
                if "created_at" in doc and doc["created_at"]:
                    doc["created_at"] = doc["created_at"].strftime("%d-%m-%Y %I:%M %p")

    except Exception as e:
        current_app.logger.error(f"Error fetching document list via API: {e}")
        return jsonify({"error": "An error occurred while fetching documents."}), 500
    finally:
        if connection:
            connection.close()

    return jsonify(documents)


@main.route("/documents/edit/<int:doc_id>", methods=["GET", "POST"])
@adm_login_required
@subadmin_permission_required("DOCUMENTS.edit_document")
def editDocument(doc_id):
    connection = get_db_connection()
    try:
        if request.method == "POST":

            form_data = request.form
            title = form_data.get("title")
            extracted_data_str = form_data.get("extracted_data")

            tags_list = request.form.getlist("tags")

            if not title:
                flash("Title is a required field.", "error")

                return redirect(url_for("main.editDocument", doc_id=doc_id))

            try:
                json.loads(extracted_data_str)
            except json.JSONDecodeError:
                flash("Error: Extracted data is not in a valid JSON format.", "danger")
                return redirect(url_for("main.editDocument", doc_id=doc_id))

            with connection.cursor() as cursor:

                sql_update_doc = """
                    UPDATE documents 
                    SET title = %s, category = %s, sub_category = %s, extracted_data = %s 
                    WHERE id = %s
                """
                params_doc = (
                    title,
                    form_data.get("category"),
                    form_data.get("sub_category"),
                    extracted_data_str,
                    doc_id,
                )
                cursor.execute(sql_update_doc, params_doc)

                cursor.execute(
                    "DELETE FROM document_tags WHERE document_id = %s", (doc_id,)
                )

                if tags_list:

                    placeholders = ",".join(["%s"] * len(tags_list))
                    sql_find_tags = (
                        f"SELECT t_id FROM tags WHERE tag_name IN ({placeholders})"
                    )
                    cursor.execute(sql_find_tags, tags_list)
                    tag_ids = [row["t_id"] for row in cursor.fetchall()]

                    if tag_ids:
                        sql_link_tags = "INSERT INTO document_tags (document_id, tag_id) VALUES (%s, %s)"
                        link_params = [(doc_id, tag_id) for tag_id in tag_ids]
                        cursor.executemany(sql_link_tags, link_params)

            connection.commit()

            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                "Edit",
                "Documents/Edit",
                f"Edited document '{title}' with ID: {doc_id}",
            )
            flash("Document updated successfully!", "success")
            return redirect(url_for("main.documentList"))

        else:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:

                cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
                doc = cursor.fetchone()
                if not doc:
                    flash("Document not found.", "error")
                    return redirect(url_for("main.documentList"))

                cursor.execute(
                    """
                    SELECT t.tag_name 
                    FROM tags t
                    INNER JOIN document_tags dt ON t.t_id = dt.tag_id
                    WHERE dt.document_id = %s
                """,
                    (doc_id,),
                )

                doc["tags"] = [row["tag_name"] for row in cursor.fetchall()]

                try:
                    parsed_json = json.loads(doc["extracted_data"])
                    doc["extracted_data"] = json.dumps(parsed_json, indent=4)
                except (json.JSONDecodeError, TypeError):
                    pass

                cursor.execute(
                    "SELECT category_name FROM categories ORDER BY category_name ASC"
                )
                all_categories = cursor.fetchall()
                cursor.execute(
                    "SELECT sub_category_name FROM sub_categories ORDER BY sub_category_name ASC"
                )
                all_subcategories = cursor.fetchall()
                cursor.execute("SELECT tag_name FROM tags ORDER BY tag_name ASC")
                all_tags = cursor.fetchall()

            return render_template(
                "editDocument.html",
                doc=doc,
                categories=all_categories,
                subcategories=all_subcategories,
                all_tags=all_tags,
            )

    except Exception as e:
        connection.rollback()
        current_app.logger.error(
            f"An unexpected error occurred while editing document {doc_id}: {e}"
        )
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

        if file_path:
            file_key = file_path.split("/")[-1]
            delete_file_from_s3(file_key, current_app.config.get("AWS_S3_BUCKET"))

        log_user_activity(
            session.get("admin_id") or session.get("subadmin_id"),
            session.get("admin_name") or session.get("subadmin_name"),
            session.get("user_type"),
            "Delete",
            "Documents/Delete",
            f"Deleted document with ID: {doc_id}",
        )

        flash("Document deleted successfully!", "success")
    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"Error deleting document {doc_id}: {e}")
        flash(f"An error occurred: {str(e)}", "error")
    finally:
        if connection:
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
                sql = (
                    "INSERT INTO subadminroles (role_name, permissions) VALUES (%s, %s)"
                )
                cursor.execute(sql, (role_name, permissions_json))
            connection.commit()

            log_user_activity(
                session.get("admin_id") or session.get("subadmin_id"),
                session.get("admin_name") or session.get("subadmin_name"),
                session.get("user_type"),
                "Create",
                "Users/Roles",
                f"Created new role '{role_name}'",
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
                    "view_sub_categories": request.form.get(
                        "view_sub_categories", "No"
                    ),
                    "create_sub_category": request.form.get(
                        "create_sub_category", "No"
                    ),
                    "edit_sub_category": request.form.get("edit_sub_category", "No"),
                    "delete_sub_category": request.form.get(
                        "delete_sub_category", "No"
                    ),
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
                    "view_user_activities": request.form.get(
                        "view_user_activities", "No"
                    ),
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
                f"Edited role '{role_name}' with ID: {role_id}",
            )

            flash(f'Role "{role_name}" updated successfully!', "success")
            return redirect(url_for("main.usersRoles"))

        else:
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
                "SELECT COUNT(*) as user_count FROM subadmin WHERE role_id = %s",
                (role_id,),
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
            f"Deleted role '{role_name}' with ID: {role_id}",
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

            with connection.cursor() as cursor:

                cursor.execute(
                    "SELECT superadmin_email FROM superadmin WHERE superadmin_email=%s",
                    (email,),
                )
                if cursor.fetchone():
                    flash(
                        f'Email "{email}" already exists in super admin portal. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.createUser"))

                cursor.execute(
                    "SELECT admin_email FROM admin WHERE admin_email=%s", (email,)
                )
                if cursor.fetchone():
                    flash(
                        f'Email "{email}" already exists in admin portal. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.createUser"))

                cursor.execute(
                    "SELECT subadmin_email FROM subadmin WHERE subadmin_email=%s",
                    (email,),
                )
                if cursor.fetchone():
                    flash(
                        f'Email "{email}" already exists in subadmin portal. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.createUser"))

                cursor.execute(
                    "SELECT subadmin_username FROM subadmin WHERE subadmin_username=%s",
                    (username,),
                )
                if cursor.fetchone():
                    flash(
                        f'Username "{username}" is already taken. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.createUser"))

            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

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
                f"Created new user '{name}' with email '{email}' and role_id '{role_id}'",
            )

            flash(f'User "{name}" created successfully!', "success")
            return redirect(url_for("main.userList"))

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
            flash(
                f'An account with the username "{username}" already exists.', "danger"
            )
        else:
            flash(
                "A database error occurred. The username or email might already be taken.",
                "danger",
            )
        return redirect(url_for("main.createUser"))
    except Exception as e:
        connection.rollback()
        current_app.logger.error(f"Error creating user: {e}")
        flash("An error occurred while creating the user.", "danger")
        return redirect(url_for("main.createUser"))
    finally:
        connection.close()


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

            if not all([name, email, username, role_id]):
                flash("All fields except password are required.", "danger")
                return redirect(url_for("main.editUser", user_id=user_id))

            if password and password != confirm_password:
                flash("New passwords do not match.", "danger")
                return redirect(url_for("main.editUser", user_id=user_id))

            with connection.cursor() as cursor:

                cursor.execute(
                    "SELECT superadmin_email FROM superadmin WHERE superadmin_email=%s",
                    (email,),
                )
                if cursor.fetchone():
                    flash(
                        f'Email "{email}" already exists in super admin portal. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.editUser", user_id=user_id))

                cursor.execute(
                    "SELECT admin_email FROM admin WHERE admin_email=%s", (email,)
                )
                if cursor.fetchone():
                    flash(
                        f'Email "{email}" already exists in admin portal. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.editUser", user_id=user_id))

                cursor.execute(
                    "SELECT subadmin_id, subadmin_email FROM subadmin WHERE subadmin_email=%s AND subadmin_id != %s",
                    (email, user_id),
                )
                if cursor.fetchone():
                    flash(
                        f'Email "{email}" already exists in subadmin portal. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.editUser", user_id=user_id))

                cursor.execute(
                    "SELECT subadmin_id, subadmin_username FROM subadmin WHERE subadmin_username=%s AND subadmin_id != %s",
                    (username, user_id),
                )
                if cursor.fetchone():
                    flash(
                        f'Username "{username}" is already taken. Please choose another.',
                        "danger",
                    )
                    return redirect(url_for("main.editUser", user_id=user_id))

            with connection.cursor() as cursor:
                if password:
                    hashed_password = bcrypt.hashpw(
                        password.encode("utf-8"), bcrypt.gensalt()
                    ).decode("utf-8")

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
                f"Edited user '{name}' with ID: {user_id}",
            )

            flash(f'User "{name}" updated successfully!', "success")
            return redirect(url_for("main.userList"))

        else:
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM subadmin WHERE subadmin_id = %s", (user_id,)
                )
                user = cursor.fetchone()
                if not user:
                    flash("User not found.", "danger")
                    return redirect(url_for("main.userList"))

                cursor.execute(
                    "SELECT r_id, role_name FROM subadminroles ORDER BY role_name ASC"
                )
                all_roles = cursor.fetchall()

            return render_template(
                "create_edit_user.html", user=user, all_roles=all_roles
            )

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
            cursor.execute(
                "SELECT subadmin_username FROM subadmin WHERE subadmin_id = %s",
                (user_id,),
            )
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
    page = request.args.get("page", 1, type=int)
    per_page = 20
    event_type = request.args.get("event_type")
    user_filter = request.args.get("user")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")

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
            total = cursor.fetchone()["total"]

            query += " ORDER BY id DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])

            cursor.execute(query, tuple(params))
            activities = cursor.fetchall()

            cursor.execute(
                "SELECT DISTINCT event_type FROM user_activities ORDER BY event_type"
            )
            event_types = [row["event_type"] for row in cursor.fetchall()]

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
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": total_pages,
        "has_prev": page > 1,
        "has_next": page * per_page < total,
        "prev_num": page - 1,
        "next_num": page + 1,
        "iter_pages": lambda: page_items,
    }

    return render_template(
        "usersActivities.html",
        activities=activities,
        pagination=pagination,
        event_types=event_types,
        current_filters={
            "event_type": event_type,
            "user": user_filter,
            "date_from": date_from,
            "date_to": date_to,
        },
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

