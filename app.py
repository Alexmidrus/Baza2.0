from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "items.json"

# Uploads
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
ALLOWED_EXT = {"jpg", "jpeg", "png", "webp"}

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")  # поменяйте в env

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))


# ---------- Data layer (JSON store) ----------
def _ensure_data_file() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text(json.dumps({"houses": [], "gazebos": []}, ensure_ascii=False, indent=2), encoding="utf-8")


def load_data() -> Dict[str, Any]:
    _ensure_data_file()
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def save_data(data: Dict[str, Any]) -> None:
    _ensure_data_file()
    DATA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def new_id(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(6)}"


def allowed_image(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXT


def upload_subdir(item_type: str) -> Path:
    sub = "houses" if item_type == "houses" else "gazebos"
    p = UPLOAD_DIR / sub
    p.mkdir(parents=True, exist_ok=True)
    return p


def delete_item_image_if_exists(item: Dict[str, Any]) -> None:
    """Delete linked image file from disk if it is under /static/uploads."""
    img = item.get("image")
    if not img or not isinstance(img, str):
        return
    # Only allow deleting within our static dir
    if not img.startswith("/static/uploads/"):
        return
    file_path = BASE_DIR / img.lstrip("/")
    try:
        if file_path.exists() and file_path.is_file():
            file_path.unlink()
    except Exception:
        # In production, log this.
        pass


# ---------- Auth ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


# ---------- Public site ----------
@app.get("/")
def index():
    """
    Публичная страница сайта.
    Данные домиков/беседок берём из JSON.
    """
    data = load_data()
    return render_template(
        "site/index.html",
        houses=data.get("houses", []),
        gazebos=data.get("gazebos", []),
    )


# ---------- Admin views ----------
@app.get("/admin/login")
def admin_login():
    return render_template("admin/login.html")


@app.post("/admin/login")
def admin_login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return redirect(url_for("admin_panel"))

    flash("Неверный логин или пароль.", "error")
    return redirect(url_for("admin_login"))


@app.post("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.post("/admin/reset-password")
def admin_reset_password():
    # Демонстрация восстановления (в проде: email + токен + отправка письма)
    email = (request.form.get("email") or "").strip()
    flash(f"Если аккаунт для {email} существует, мы отправили инструкцию.", "info")
    return redirect(url_for("admin_login"))


@app.get("/admin")
@login_required
def admin_panel():
    return render_template("admin/panel.html")


# ---------- Admin API (CRUD) ----------
ItemType = Literal["houses", "gazebos"]


def _validate_type(item_type: str) -> ItemType:
    if item_type not in ("houses", "gazebos"):
        abort(400, description="Invalid type")
    return item_type  # type: ignore[return-value]


@app.get("/api/admin/items")
@login_required
def api_list_items():
    item_type = _validate_type(request.args.get("type", "houses"))
    data = load_data()
    return jsonify({"items": data.get(item_type, [])})


@app.post("/api/admin/items")
@login_required
def api_create_item():
    payload = request.get_json(force=True, silent=False) or {}
    item_type = _validate_type(payload.get("type", "houses"))

    data = load_data()
    items: List[Dict[str, Any]] = data.get(item_type, [])

    if item_type == "houses":
        item = {
            "id": new_id("h"),
            "name": str(payload.get("name", "")).strip(),
            "price": int(payload.get("price", 0)),
            "status": payload.get("status", "active"),
            "beds": int(payload.get("beds", 4)),
            "wc": bool(payload.get("wc", True)),
            "kitchen": bool(payload.get("kitchen", True)),
            "image": payload.get("image", "placeholder"),
        }
    else:
        item = {
            "id": new_id("g"),
            "name": str(payload.get("name", "")).strip(),
            "price": int(payload.get("price", 0)),
            "status": payload.get("status", "active"),
            "gazType": payload.get("gazType", "small"),
            "capacity": int(payload.get("capacity", 10)),
            "image": payload.get("image", "placeholder"),
        }

    if not item["name"]:
        abort(400, description="Name is required")

    items.insert(0, item)
    data[item_type] = items
    save_data(data)
    return jsonify({"ok": True, "item": item}), 201


@app.put("/api/admin/items/<item_id>")
@login_required
def api_update_item(item_id: str):
    payload = request.get_json(force=True, silent=False) or {}
    item_type = _validate_type(payload.get("type", "houses"))

    data = load_data()
    items: List[Dict[str, Any]] = data.get(item_type, [])

    idx = next((i for i, x in enumerate(items) if x.get("id") == item_id), None)
    if idx is None:
        abort(404, description="Not found")

    current = items[idx]
    current["name"] = str(payload.get("name", current.get("name", ""))).strip()
    current["price"] = int(payload.get("price", current.get("price", 0)))
    current["status"] = payload.get("status", current.get("status", "active"))
    current["image"] = payload.get("image", current.get("image", "placeholder"))

    if item_type == "houses":
        current["beds"] = int(payload.get("beds", current.get("beds", 4)))
        current["wc"] = bool(payload.get("wc", current.get("wc", True)))
        current["kitchen"] = bool(payload.get("kitchen", current.get("kitchen", True)))
    else:
        current["gazType"] = payload.get("gazType", current.get("gazType", "small"))
        current["capacity"] = int(payload.get("capacity", current.get("capacity", 10)))

    if not current["name"]:
        abort(400, description="Name is required")

    items[idx] = current
    data[item_type] = items
    save_data(data)
    return jsonify({"ok": True, "item": current})


@app.post("/api/admin/items/<item_id>/image")
@login_required
def api_upload_item_image(item_id: str):
    """Upload/replace image for a конкретной записи.

    Form-data:
      - type: houses|gazebos
      - image: file
    """
    item_type = _validate_type(request.form.get("type", "houses"))

    if "image" not in request.files:
        abort(400, description="No file field 'image'")

    file = request.files["image"]
    if not file or not file.filename:
        abort(400, description="Empty filename")

    filename = secure_filename(file.filename)
    if not allowed_image(filename):
        abort(400, description="Unsupported file type")

    data = load_data()
    items: List[Dict[str, Any]] = data.get(item_type, [])
    idx = next((i for i, x in enumerate(items) if x.get("id") == item_id), None)
    if idx is None:
        abort(404, description="Not found")

    item = items[idx]

    # Remove old image if exists
    delete_item_image_if_exists(item)

    ext = filename.rsplit(".", 1)[1].lower()
    dst_dir = upload_subdir(item_type)
    dst_name = f"{item_id}.{ext}"
    dst_path = dst_dir / dst_name
    file.save(dst_path)

    rel_url = f"/static/uploads/{'houses' if item_type == 'houses' else 'gazebos'}/{dst_name}"
    item["image"] = rel_url
    items[idx] = item
    data[item_type] = items
    save_data(data)

    return jsonify({"ok": True, "image": rel_url, "item": item})


@app.delete("/api/admin/items/<item_id>")
@login_required
def api_delete_item(item_id: str):
    item_type = _validate_type(request.args.get("type", "houses"))
    data = load_data()
    items: List[Dict[str, Any]] = data.get(item_type, [])

    idx = next((i for i, x in enumerate(items) if x.get("id") == item_id), None)
    if idx is None:
        abort(404, description="Not found")

    # delete linked image from disk
    delete_item_image_if_exists(items[idx])

    items.pop(idx)
    data[item_type] = items
    save_data(data)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True)
