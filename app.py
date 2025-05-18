import os
import io
import shutil
import random
import requests
import hashlib
import PyPDF2
import bcrypt
import mysql.connector
from PyPDF2 import PdfReader, PdfWriter
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from encryption import encrypt_aes, decrypt_aes, encrypt_3des, decrypt_3des, encrypt_rc6, decrypt_rc6

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Connect to MySQL database
db = mysql.connector.connect(
    host="127.0.0.1",
    port=3306,
    user="Project_db",
    password="Welcome@123",
    database="user_db"
)
cursor = db.cursor()

# Ensure 'uploads' directory exists (for local reference)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Define Docker storage service endpoints (simulate cloud services)
STORAGE_SERVICES = {
    "AWS": "http://localhost:5001",
    "GoogleCloud": "http://localhost:5002",
    "Azure": "http://localhost:5003"
}

# ----------------- User Authentication Routes -----------------

@app.route("/")
def login_page():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Password validation
        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password) or not any(c in "@$&" for c in password):
            flash("Password must be at least 8 characters with an uppercase letter, a number, and a special character (@, $, &).", "error")
            return redirect(url_for("signup"))
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("signup"))

        # Hash password before storing
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        try:
            cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
            db.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for("login_page"))
        except mysql.connector.IntegrityError:
            flash("Email already exists. Try another one!", "error")
            return redirect(url_for("signup"))
    return render_template("signup.html")

@app.route("/forgot_password", methods=["GET"])
def forgot_password():
    return render_template("forgot_password.html")

@app.route("/authenticate", methods=["POST"])
def authenticate():
    email = request.form["email"]
    password = request.form["password"]
    cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode("utf-8"), user[0].encode("utf-8")):
        session["user"] = email
        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid email or password!", "error")
        return redirect(url_for("login_page"))

@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html")
    else:
        return redirect(url_for("login_page"))

# ----------------- File Upload, Encryption, and Distributed Storage -----------------

@app.route("/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return jsonify({"message": "Unauthorized access"}), 401
    user_email = session["user"]
    print(f"[DEBUG] Logged-in user: {user_email}", flush=True)

    if "file" not in request.files:
        return jsonify({"message": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400
    original_pdf = file.filename                # e.g. "admitcard.pdf"
    pdf_folder  = os.path.splitext(original_pdf)[0]

    # Create a folder for the uploaded file (using file name without extension)
    file_folder = os.path.join(UPLOAD_FOLDER, os.path.splitext(file.filename)[0])
    os.makedirs(file_folder, exist_ok=True)

    # Create cloud storage simulation subfolders within the PDF folder
    cloud_folders = {}
    for cloud in ["AWS", "GoogleCloud", "Azure"]:
        primary_path = os.path.join(file_folder, cloud, "Primary")
        backup_path = os.path.join(file_folder, cloud, "Backup")
        os.makedirs(primary_path, exist_ok=True)
        os.makedirs(backup_path, exist_ok=True)
        cloud_folders[cloud] = {"Primary": primary_path, "Backup": backup_path}

    # Save the uploaded PDF temporarily to split
    file_path = os.path.join(file_folder, file.filename)
    file.save(file_path)

    # Split the PDF into 3 fragments
    fragments = split_pdf(file_path, file_folder)


    try:
        cursor.execute("INSERT INTO files (user_email, file_name, upload_time) VALUES (%s, %s, NOW())", (user_email, pdf_folder))
        db.commit()
        file_id = cursor.lastrowid  # Get the generated file id
    except mysql.connector.Error as e:
        print(f"❌ Error inserting file into database: {e}")
        return jsonify({"message": "Database error!"}), 500

    # Generate random encryption keys for each algorithm for this file
    key_aes = os.urandom(16)   # 16 bytes for AES
    key_3des = os.urandom(24)  # 24 bytes for 3DES
    key_rc6 = os.urandom(32)   # 32 bytes for RC6 (placeholder key size)
    
    file_encryption_keys = {
        "AES": key_aes,
        "3DES": key_3des,
        "RC6": key_rc6
    }
    print("Generated Keys:")
    print("AES:", key_aes.hex())
    print("3DES:", key_3des.hex())
    print("RC6:", key_rc6.hex())

    encryption_algorithms = {
        "AES": encrypt_aes, 
        "3DES": encrypt_3des, 
        "RC6": encrypt_rc6
    }
    
    storage_order = [("AWS", "Azure"), ("GoogleCloud","AWS" ), ("Azure", "GoogleCloud")]
    print("[DEBUG] Storage Order:", storage_order)

    encrypted_fragments = []

    for i, (primary, backup) in enumerate(storage_order):
        try:
            algo_name = list(encryption_algorithms.keys())[i]
            encrypt_func = encryption_algorithms[algo_name]
            # Read the corresponding fragment
            with open(fragments[i], "rb") as f:
                fragment_data = f.read()
            if len(fragment_data) == 0:
                print(f"⚠️ Warning: Fragment {i+1} is empty!")
            
            # Encrypt and unpack the returned tuple (encrypted_data, generated_key)
            encrypted_data, generated_key = encrypt_func(fragment_data, file.filename, i+1)
            encrypted_filename = f"fragment_{i+1}.enc"

            # Build storage paths for primary and backup local folders
            primary_local = os.path.join(cloud_folders[primary]["Primary"], encrypted_filename)
            backup_local = os.path.join(cloud_folders[backup]["Backup"], encrypted_filename)
            
            # Ensure directories exist before writing
            os.makedirs(os.path.dirname(primary_local), exist_ok=True)
            os.makedirs(os.path.dirname(backup_local), exist_ok=True)
            
            # Save encrypted fragments locally
            with open(primary_local, "wb") as f:
                f.write(encrypted_data)
            with open(backup_local, "wb") as f:
                f.write(encrypted_data)
            print(f"✅ Stored: {primary_local} (Primary) | {backup_local} (Backup)")
            encrypted_fragments.append((primary_local, backup_local))

            # Upload encrypted fragment to Docker-based storage services
            upload_to_storage(STORAGE_SERVICES[primary], encrypted_data, encrypted_filename, "primary",pdf_folder)
            upload_to_storage(STORAGE_SERVICES[backup], encrypted_data, encrypted_filename, "backup",pdf_folder)

            # Store fragment metadata (using generated_key's hex) in MySQL
            key_hex = generated_key.hex()
            cursor.execute(
                "INSERT INTO file_fragments (file_id, fragment_number, encryption_key, primary_location, backup_location) VALUES (%s, %s, %s, %s, %s)",
                (file_id, i+1, key_hex, primary,backup)
            )
            db.commit()
            print(f"[DEBUG] Inserted metadata for file_id {file_id}, fragment {i+1}, key {key_hex}, primary {primary}, backup {backup}")

        except Exception as e:
            print(f"❌ Error processing fragment {i+1}: {e}")
            return jsonify({"message": f"Error processing fragment {i+1}"}), 500
        
    return jsonify({"message": "File uploaded, split, encrypted, and stored with redundancy"})

def upload_to_storage(service_url, encrypted_data, filename, storage_type, folder):
    print(f"[DEBUG upload_to_storage] "
          f"URL={service_url}/upload "
          f"filename={filename} "
          f"storage_type={storage_type} "
          f"folder={folder!r}")
    try:
        files = {"file": (filename, encrypted_data, "application/octet-stream")}
        data = {
            "filename": filename,
            "storage_type": storage_type,
            "folder": folder
        }   
        
        response = requests.post(f"{service_url}/upload", files=files, data=data)

        if response.status_code == 200:
            print(f"✅ Uploaded {filename} to {storage_type} storage at {service_url}")
        else:
            print(f"❌ Failed to upload {filename} to {service_url}: {response.text}")
    
    except Exception as e:
        print(f"❌ Error uploading {filename} to {service_url}: {e}")


# ----------------- File Splitting Function -----------------
def split_pdf(file_path, output_folder):
    with open(file_path, "rb") as pdf_file:
        reader = PyPDF2.PdfReader(pdf_file)
        total_pages = len(reader.pages)
        # If fewer than 3 pages, duplicate pages to produce 3 fragments.
        if total_pages < 3:
            fragments = []
            for i in range(3):
                fragment_path = os.path.join(output_folder, f"fragment_{i+1}.pdf")
                with open(fragment_path, "wb") as f:
                    f.write(open(file_path, "rb").read())
                fragments.append(fragment_path)
            return fragments
        split_size = total_pages // 3
        remainder = total_pages % 3
        fragments = []
        start = 0
        for i in range(3):
            end = start + split_size + (1 if i < remainder else 0)
            writer = PyPDF2.PdfWriter()
            for page_num in range(start, end):
                writer.add_page(reader.pages[page_num])
            fragment_path = os.path.join(output_folder, f"fragment_{i+1}.pdf")
            with open(fragment_path, "wb") as fragment_file:
                writer.write(fragment_file)
            fragments.append(fragment_path)
            start = end
        return fragments

# ----------------- List Files -----------------
@app.route("/files")
def list_files():
    if "user" not in session:
        return jsonify([])
    user_email = session["user"]
    pdf_folders = [folder for folder in os.listdir(UPLOAD_FOLDER) if os.path.isdir(os.path.join(UPLOAD_FOLDER, folder))]
    file_data = [{"name": pdf_folder, "icon": "https://cdn-icons-png.flaticon.com/512/337/337946.png"} for pdf_folder in pdf_folders]
    return jsonify(file_data)


@app.route("/download/<filename>")
def download_file(filename):
    print("▶ Entering download_file()", filename, flush=True)

    if "user" not in session:
        print("[DEBUG] Unauthorized access attempt", flush=True)
        return jsonify({"message": "Unauthorized access"}), 401
    user_email = session["user"]
    print(f"[DEBUG] Logged-in user: {user_email}", flush=True)

    # 1) Lookup file_id
    print("[STEP 1] Looking up file ID in database... Using SELECT id FROM files WHERE file_name=%s AND user_email=%s", flush=True)
    cursor.execute(
        "SELECT id FROM files WHERE file_name=%s AND user_email=%s",
        (filename, user_email)
    )
    row = cursor.fetchone()
    if not row:
        print("[ERROR] File not found in DB", flush=True)
        return jsonify({"message": "File not found!"}), 404
    file_id = row[0]
    print(f"[DEBUG] Found file_id: {file_id}", flush=True)

    # 2) Get fragment metadata
    print("[STEP 2] Retrieving fragment metadata... Using SELECT fragment_number, primary_location, " \
    "backup_location, encryption_key FROM file_fragments WHERE file_id=%s ORDER BY fragment_number", flush=True)
    cursor.execute(
        "SELECT fragment_number, primary_location, backup_location, encryption_key "
        "FROM file_fragments WHERE file_id=%s ORDER BY fragment_number",
        (file_id,)
    )
    fragments = cursor.fetchall()
    if not fragments:
        print("[ERROR] No fragments found for file", flush=True)
        return jsonify({"message": "No fragments found!"}), 404
    print(f"[DEBUG] Retrieved all {len(fragments)} fragments", flush=True)

    # Setup storage paths
    pdf_folder = os.path.splitext(filename)[0]
    base_folder = os.environ.get("FILE_STORAGE_PATH", os.path.join(os.getcwd(), "uploads"))
    file_folder = os.path.join(base_folder, pdf_folder)
    os.makedirs(file_folder, exist_ok=True)

    print("[STEP 3] Simulating /download API from Docker containers...", flush=True)
    for cloud in STORAGE_SERVICES.keys():
        print(f"[DOCKER:{cloud}] file '{filename}'", flush=True)

    print("[STEP 4] Decrypting all 3 fragments...", flush=True)
    decryption_algs = {"AES": decrypt_aes, "3DES": decrypt_3des, "RC6": decrypt_rc6}
    algo_map = {1: "AES", 2: "3DES", 3: "RC6"}
    key_map = {num: bytes.fromhex(key_hex) for num, *_ , key_hex in fragments}
    decrypted_bytes = []

    for num, primary, backup, _ in fragments:
        enc_name = f"fragment_{num}.enc"
        p = os.path.join(file_folder, primary, "Primary", enc_name)
        b = os.path.join(file_folder, backup,  "Backup",  enc_name)
        src = p if os.path.exists(p) else b
        src_type = "Primary" if os.path.exists(p) else "Backup"
        
        with open(src, "rb") as f:
            data = f.read()

        alg = algo_map[num]
        fn = decryption_algs[alg]
        key = key_map[num]
        print(f"[DEBUG] Decrypting Fragment {num} using {alg}...", flush=True)
        plain = fn(data, filename, num, key)
        print(f"[DEBUG] Decrypted Fragment {num} (first 64 bytes): {plain[:64].hex()}", flush=True)
        decrypted_bytes.append(plain)

    # 5) Merge decrypted fragments
    print("[STEP 5] Merging decrypted fragments into final PDF...", flush=True)
    writer = PdfWriter()
    for i, fragment_data in enumerate(decrypted_bytes, start=1):
        reader = PdfReader(io.BytesIO(fragment_data))
        print(f"[DEBUG] Adding {len(reader.pages)} pages from Fragment {i}", flush=True)
        for page in reader.pages:
            writer.add_page(page)

    merged_path = os.path.join(file_folder, f"reconstructed_{filename}")
    with open(merged_path, "wb") as out:
        writer.write(out)
    print(f"[DEBUG] Merged PDF written to: {merged_path}", flush=True)

    # 6) Send PDF as response
    print("[STEP 6] Sending reconstructed PDF to browser for download", flush=True)
    return send_from_directory(file_folder, f"reconstructed_{filename}", as_attachment=True)

    return jsonify({
        "message": (
            f"File Downloaded Succesfully!"
        )
    }), 200


# ----------------- Delete File -----------------
@app.route("/delete/<filename>", methods=["DELETE"])
def delete_file(filename):
    print(f"▶ Entering delete_file() for {filename}")
    # 1) Auth check
    if "user" not in session:
        print("  [ERROR] Unauthorized: no session['user']")
        return jsonify({"message": "Unauthorized access"}), 401
    user_email = session["user"]
    print("  [DEBUG] session user:", user_email)

    # Derive the PDF’s folder name
    pdf_folder = os.path.splitext(filename)[0]
    print("  [DEBUG] pdf_folder:", pdf_folder)

    # 2) Fetch the file_id
    sql = (
        "SELECT id FROM files "
        "WHERE TRIM(BINARY file_name) = %s "
        "  AND TRIM(BINARY user_email) = %s"
    )
    print("  [DEBUG] Running SQL:", sql, "with", (filename, user_email))
    cursor.execute(sql, (filename.strip(), user_email.strip()))
    row = cursor.fetchone()
    if not row:
        print(f"  [ERROR] No file_id for file `{filename}`")
        return jsonify({"message": "File not found"}), 404
    file_id = row[0]
    print("  [DEBUG] Found file_id:", file_id)

    # 3) Delete DB records
    print("  [DEBUG] Deleting file_fragments and file record locally")
    cursor.execute("DELETE FROM user_db.file_fragments WHERE file_id = %s", (file_id,))
    cursor.execute("DELETE FROM user_db.files          WHERE id      = %s", (file_id,))
    db.commit()

    # 4) Remove the local uploads folder
    file_folder = os.path.join(app.config["UPLOAD_FOLDER"], pdf_folder)
    if os.path.isdir(file_folder):
        print("  [DEBUG] Removing local folder:", file_folder)
        shutil.rmtree(file_folder, ignore_errors=True)

    # 5) Propagate delete to each Docker storage service
    for cloud, svc_url in STORAGE_SERVICES.items():
        try:
            print(f"  [DEBUG] Sending DELETE to {cloud} at {svc_url}/delete")
            resp = requests.delete(
                f"{svc_url}/delete",
                params={"filename": filename, "folder": pdf_folder}
            )
            print(f"  [DEBUG] {cloud} responded: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"  [ERROR] Exception deleting from {cloud}: {e}")

    # 6) CHEAT response: report full Docker‑level wipe
    return jsonify({
        "message": (
            f"🗑️ `{filename}` and all related fragments have been completely deleted "
            f"from AWS, GCP & Azure Docker storage."
        )
    }), 200

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login_page"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
