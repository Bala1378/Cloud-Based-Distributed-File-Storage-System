from flask import Flask, request, jsonify, send_file
import os, shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)
STORAGE_NAME = os.environ.get("STORAGE_NAME", "AWS")


BASE    = f"{STORAGE_NAME.lower()}_storage"
PRIMARY = os.path.join(BASE, "primary")
BACKUP  = os.path.join(BASE, "backup")
for d in (PRIMARY, BACKUP):
    os.makedirs(d, exist_ok=True)


@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    fn   = request.form.get("filename")
    st   = request.form.get("storage_type")
    fld  = secure_filename(request.form.get("folder", ""))

    if not file or not fn or st not in ("primary", "backup"):
        return jsonify({"error": "Invalid params"}), 400

    base = PRIMARY if st == "primary" else BACKUP
    if fld:
        base = os.path.join(base, fld)
        os.makedirs(base, exist_ok=True)

    path = os.path.join(base, secure_filename(fn))
    file.save(path)

    print(f"[UPLOAD:{STORAGE_NAME}] {path}", flush=True)
    return jsonify({"message": "Stored", "path": path}), 200


@app.route("/download", methods=["GET"])
def download_fragment():
    filename = request.args.get("filename", "")
    folder   = secure_filename(request.args.get("folder", ""))

    if not filename or not folder:
        return jsonify({"error": "Missing filename or folder"}), 400

    folder_path_primary = os.path.join(PRIMARY, folder)
    folder_path_backup  = os.path.join(BACKUP, folder)

    found_file = None
    for subdir in [folder_path_primary, folder_path_backup]:
        if os.path.exists(subdir):
            for f in os.listdir(subdir):
                if f.endswith(".enc"):
                    found_file = os.path.join(subdir, f)
                    break
        if found_file:
            break

    if not found_file:
        return jsonify({"error": "File not found"}), 404

    msg = f"📥 Docker {STORAGE_NAME} got download for fragment '{os.path.basename(found_file)}' in '{folder}'"
    print(f"🗄️ [DOWNLOAD] {msg}", flush=True)

    return jsonify({"message": msg}), 200


@app.route("/delete", methods=["DELETE"])
def delete_fragments():
    filename = request.args.get("filename")
    folder = request.args.get("folder")

    if not folder:
        return jsonify({"message": "❌ Missing folder parameter"}), 400

    primary_path = os.path.join(PRIMARY, folder)
    backup_path  = os.path.join(BACKUP, folder)

    deleted_primary = deleted_backup = False

    if os.path.exists(primary_path):
        shutil.rmtree(primary_path)
        print(f"🗑️ [DELETE] Deleted PRIMARY folder: {primary_path}")
        deleted_primary = True
    else:
        print(f"⚠️ [DELETE] PRIMARY folder not found: {primary_path}")

    if os.path.exists(backup_path):
        shutil.rmtree(backup_path)
        print(f"🗑️ [DELETE] Deleted BACKUP folder: {backup_path}")
        deleted_backup = True
    else:
        print(f"⚠️ [DELETE] BACKUP folder not found: {backup_path}")

    if deleted_primary or deleted_backup:
        return jsonify({
            "message": f"✅ {filename} fragments deleted from Docker ({folder})",
            "primary_deleted": deleted_primary,
            "backup_deleted": deleted_backup
        }), 200
    else:
        return jsonify({
            "message": f"⚠️ No fragments found for {filename} in Docker",
            "primary_deleted": False,
            "backup_deleted": False
        }), 404


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)
