"""
ACE Business Management Systems - backend (single file).
Every piece of data (accounts, sessions, business records, files, audit logs) lives in Backblaze B2
through its S3-compatible API. There is no other database.

Required environment variables (never put these in code or GitHub):
  B2_KEY_ID, B2_APP_KEY          Backblaze application key (restrict it to the acebusiness bucket)
  B2_BUCKET                      default: acebusiness
  B2_ENDPOINT                    default: https://s3.eu-central-003.backblazeb2.com
  ADMIN_USER                     default: ACEt
  ADMIN_PASSWORD_HASH            output of werkzeug generate_password_hash (preferred)
  ADMIN_PASSWORD                 plain fallback if no hash is set (admin login is disabled if neither is set)
  ALLOWED_ORIGINS                comma-separated origins allowed to call the API (not needed if index.html is served by this app)
Run on Render with ONE worker (writes are serialised with in-process locks):
  gunicorn app:app --workers 1 --threads 8 --timeout 60
"""
import os, re, io, csv, json, time, uuid, hmac, math, hashlib, secrets, threading
from datetime import datetime, timezone, timedelta
from functools import wraps

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify, g, send_from_directory, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------------------------------------------------------- setup
ENDPOINT = os.environ.get("B2_ENDPOINT", "https://s3.eu-central-003.backblazeb2.com")
BUCKET = os.environ.get("B2_BUCKET", "acebusiness")
REGION = (re.search(r"s3\.([^.]+)\.backblazeb2", ENDPOINT) or [None, "us-west-004"])[1]
ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]

s3 = boto3.client(
    "s3", endpoint_url=ENDPOINT, region_name=REGION,
    aws_access_key_id=os.environ.get("B2_KEY_ID"), aws_secret_access_key=os.environ.get("B2_APP_KEY"),
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                  retries={"max_attempts": 4, "mode": "standard"},
                  request_checksum_calculation="when_required", response_checksum_validation="when_required"))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024


class ApiError(Exception):
    def __init__(self, status, code, message=""):
        self.status, self.code, self.message = status, code, message or code


# ----------------------------------------------------------------------------- B2 storage layer
def get(key, default=None):
    try:
        return json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404", "NotFound"):
            return default
        raise


def put(key, obj):
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(obj, separators=(",", ":")).encode(),
                  ContentType="application/json")


def delete(key):
    s3.delete_object(Bucket=BUCKET, Key=key)


_locks, _lg = {}, threading.Lock()


def lock(name):
    with _lg:
        return _locks.setdefault(name, threading.RLock())


# ----------------------------------------------------------------------------- helpers
def now():
    return datetime.now(timezone.utc)


def iso():
    return now().isoformat(timespec="seconds")


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def nid():
    return uuid.uuid4().hex[:12]


ID_RE = re.compile(r"^[A-Za-z0-9-]{6,40}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def rid(x):
    if not isinstance(x, str) or not ID_RE.match(x):
        raise ApiError(404, "not_found", "Record not found")
    return x


def s_(v, n=200):
    v = "" if v is None else str(v).strip()
    if len(v) > n:
        raise ApiError(400, "too_long", f"Text is longer than {n} characters")
    return v


def n_(v, mn=0):
    try:
        x = float(v)
    except (TypeError, ValueError):
        raise ApiError(400, "invalid_number", "A number is required")
    if not math.isfinite(x) or x < mn or x > 1e12:
        raise ApiError(400, "invalid_number", "Number is out of range")
    return round(x, 3)


def on_(v):
    return None if v in (None, "") else n_(v)


def d_(v):
    try:
        datetime.strptime(str(v), "%Y-%m-%d")
    except ValueError:
        raise ApiError(400, "invalid_date", "Use YYYY-MM-DD")
    return str(v)


def body():
    b = request.get_json(silent=True)
    if not isinstance(b, dict):
        raise ApiError(400, "invalid_json", "Send a JSON object")
    return b


def ym(d=None):
    return (d or now()).strftime("%Y%m")


# ----------------------------------------------------------------------------- roles, plans
ROLES = {
    "owner": ["*"],
    "manager": ["items.*", "customers.*", "suppliers.*", "expenses.*", "invoices.*", "sales.*",
                "reports.read", "export.read", "tickets.*", "files.*", "audit.read"],
    "cashier": ["items.read", "customers.read", "customers.create", "sales.create", "sales.read",
                "invoices.read", "files.read", "tickets.create"],
}
DEFAULT_PLANS = {"Free": {"max_users": 1, "max_items": 50}, "Starter": {"max_users": 5, "max_items": 500},
                 "Business": {"max_users": 25, "max_items": 10000}, "Enterprise": {"max_users": 1000, "max_items": 100000}}
METHODS = ["Cash", "M-Pesa", "Card", "Bank", "Credit"]


def can(role, p):
    return any(x == "*" or x == p or (x.endswith(".*") and p.startswith(x[:-1])) for x in ROLES.get(role, []))


def need(p):
    if not can(g.role, p):
        raise ApiError(403, "forbidden", "You do not have permission for this action")


def plan_limit(key):
    plans = get("platform/plans.json", DEFAULT_PLANS)
    return plans.get(g.prof.get("plan", "Free"), DEFAULT_PLANS["Free"]).get(key, 0)


# ----------------------------------------------------------------------------- keys (tenant always from session)
def K(*parts):
    return "/".join(["biz", g.bid, *parts])


_pcache = {}


def profile(bid, fresh=False):
    c = _pcache.get(bid)
    if c and not fresh and time.time() - c[0] < 15:
        return c[1]
    p = get(f"biz/{bid}/profile.json")
    _pcache[bid] = (time.time(), p)
    return p


def save_profile(p):
    put(K("profile.json"), p)
    _pcache[g.bid] = (time.time(), p)
    with lock("platform"):
        idx = get("platform/businesses.json", {})
        idx[g.bid] = {"name": p["name"], "owner": p.get("owner_email"), "phone": p.get("phone"), "plan": p["plan"],
                      "status": p["status"], "type": p["type"], "created": p["created"]}
        put("platform/businesses.json", idx)


def audit(action, module, rec=None, old=None, new=None):
    try:
        with lock("audit" + g.bid):
            key = K("audit", ym() + ".json")
            log = get(key, [])
            log.append({"t": iso(), "u": g.uid, "a": action, "m": module, "r": rec, "old": old, "new": new,
                        "ip": request.remote_addr})
            put(key, log[-5000:])
    except Exception:
        app.logger.exception("audit failed")


# ----------------------------------------------------------------------------- sessions
_scache, _fails = {}, {}


def throttle(key, limit=8, window=900):
    t = time.time()
    _fails[key] = [x for x in _fails.get(key, []) if t - x < window]
    if len(_fails[key]) >= limit:
        raise ApiError(429, "too_many_attempts", "Too many attempts. Try again later.")


def new_session(uid, bid, role, admin=False, remember=False):
    tok, sid = secrets.token_urlsafe(32), nid()
    h = sha(tok)
    ttl = 30 * 86400 if remember else 12 * 3600
    rec = {"sid": sid, "uid": uid, "bid": bid, "role": role, "admin": admin, "created": iso(),
           "exp": time.time() + ttl, "ip": request.remote_addr, "ua": request.headers.get("User-Agent", "")[:120]}
    put(f"sessions/{h}.json", rec)
    if not admin:
        with lock("sx" + bid):
            idx = get(f"biz/{bid}/sessions.json", {})
            idx = {k: v for k, v in idx.items() if v.get("exp", 0) > time.time()}
            idx[sid] = {"h": h, "uid": uid, "created": rec["created"], "ip": rec["ip"], "ua": rec["ua"], "exp": rec["exp"]}
            put(f"biz/{bid}/sessions.json", idx)
    return tok


def load_session(tok):
    h = sha(tok)
    c = _scache.get(h)
    rec = c[1] if c and time.time() - c[0] < 30 else get(f"sessions/{h}.json")
    if not rec or rec["exp"] < time.time():
        return None
    _scache[h] = (time.time(), rec)
    return rec


def kill_session(bid, sid):
    with lock("sx" + bid):
        idx = get(f"biz/{bid}/sessions.json", {})
        s = idx.pop(sid, None)
        if s:
            delete(f"sessions/{s['h']}.json")
            _scache.pop(s["h"], None)
            put(f"biz/{bid}/sessions.json", idx)
        return bool(s)


def kill_user_sessions(bid, uid, keep=None):
    for sid, s in list(get(f"biz/{bid}/sessions.json", {}).items()):
        if s["uid"] == uid and sid != keep:
            kill_session(bid, sid)


def api(admin=False, public=False):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not public:
                h = request.headers.get("Authorization", "")
                s = load_session(h[7:]) if h.startswith("Bearer ") else None
                if not s:
                    raise ApiError(401, "unauthenticated", "Please log in")
                g.sid = s["sid"]
                if admin:
                    if not s.get("admin"):
                        raise ApiError(403, "forbidden", "Administrators only")
                else:
                    if s.get("admin"):
                        raise ApiError(403, "forbidden", "Use a business account")
                    g.bid, g.uid, g.role = s["bid"], s["uid"], s["role"]
                    g.prof = profile(g.bid)
                    if not g.prof:
                        raise ApiError(401, "unauthenticated", "Please log in")
                    if g.prof["status"] in ("suspended", "cancelled", "expired") and not request.path.endswith("/auth/logout"):
                        raise ApiError(403, "subscription_" + g.prof["status"], "This workspace is not active. Contact support.")
            return f(*a, **k)
        return w
    return deco


# ----------------------------------------------------------------------------- app plumbing
@app.errorhandler(ApiError)
def _e(e):
    return jsonify(error={"code": e.code, "message": e.message}), e.status


@app.errorhandler(404)
def _404(e):
    return jsonify(error={"code": "not_found", "message": "Not found"}), 404


@app.errorhandler(413)
def _413(e):
    return jsonify(error={"code": "too_large", "message": "File is too large (max 5 MB)"}), 413


@app.errorhandler(Exception)
def _500(e):
    app.logger.exception("unhandled")
    return jsonify(error={"code": "server_error", "message": "Something went wrong"}), 500


@app.before_request
def _pre():
    if request.method == "OPTIONS":
        return make_response("", 204)


@app.after_request
def _post(r):
    o = request.headers.get("Origin")
    if o and o in ORIGINS:
        r.headers["Access-Control-Allow-Origin"] = o
        r.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Idempotency-Key"
        r.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        r.headers["Vary"] = "Origin"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "same-origin"
    r.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.path.startswith("/api"):
        r.headers["Cache-Control"] = "no-store"
    else:
        r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.backblazeb2.com; connect-src 'self'; frame-ancestors 'none'")
    return r


@app.get("/")
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "index.html")


@app.get("/health")
def health():
    try:
        s3.head_bucket(Bucket=BUCKET)
        return jsonify(status="ok")
    except Exception:
        return jsonify(status="storage_unavailable"), 503


# ----------------------------------------------------------------------------- auth
DUMMY = generate_password_hash("not-a-real-password")


def public_user(u, uid):
    return {"id": uid, "name": u["name"], "email": u["email"], "role": u["role"], "active": u.get("active", True)}


def check_password(pw):
    if not isinstance(pw, str) or not (8 <= len(pw) <= 128):
        raise ApiError(400, "weak_password", "Password must be 8 to 128 characters")


@app.post("/api/v1/auth/register")
@api(public=True)
def register():
    b = body()
    name, email, phone = s_(b.get("name")), s_(b.get("email"), 254).lower(), s_(b.get("phone"), 30)
    biz = b.get("business") or {}
    bname, btype = s_(biz.get("name")), biz.get("type", "retail")
    if not name or not EMAIL_RE.match(email) or not bname:
        raise ApiError(400, "invalid_input", "Name, valid email and business name are required")
    if btype not in ("retail", "hardware", "restaurant", "salon", "pharmacy"):
        raise ApiError(400, "invalid_input", "Unknown business type")
    check_password(b.get("password"))
    col = biz.get("col") or "#0e5a63"
    if not re.match(r"^#[0-9a-fA-F]{6}$", col):
        raise ApiError(400, "invalid_input", "Invalid colour")
    plan = biz.get("plan", "Free")
    if plan not in DEFAULT_PLANS or plan == "Enterprise":
        plan = "Free"
    with lock("platform"):
        ek = f"idx/email/{sha(email)}.json"
        if get(ek):
            raise ApiError(409, "email_exists", "An account with this email already exists")
        bid, uid = uuid.uuid4().hex, nid()
        prof = {"id": bid, "name": bname, "type": btype, "loc": s_(biz.get("loc")), "phone": s_(biz.get("phone") or phone, 30),
                "owner_email": email, "cur": "KES", "tax": min(n_(biz.get("tax", 16)), 50), "foot": "Thank you for your business.",
                "col": col, "mt": int(biz.get("mt", 0)) if str(biz.get("mt", 0)) in "012" else 0, "plan": plan,
                "status": "trial", "trial_ends": (now() + timedelta(days=14)).date().isoformat(), "logo": None, "created": iso()}
        put(f"biz/{bid}/profile.json", prof)
        put(f"biz/{bid}/users.json", {uid: {"name": name, "email": email, "phone": phone, "role": "owner", "active": True,
                                             "h": generate_password_hash(b["password"]), "created": iso()}})
        put(f"biz/{bid}/meta.json", {"sale": 1000, "inv": 0, "idem": {}})
        put(ek, {"bid": bid, "uid": uid})
        idx = get("platform/businesses.json", {})
        idx[bid] = {"name": bname, "owner": email, "phone": phone, "plan": plan, "status": "trial", "type": btype, "created": prof["created"]}
        put("platform/businesses.json", idx)
    g.bid, g.uid = bid, uid
    audit("register", "auth", bid)
    return jsonify(token=new_session(uid, bid, "owner"), business=prof_out(prof)), 201


@app.post("/api/v1/auth/login")
@api(public=True)
def login():
    b = body()
    ident, pw = s_(b.get("email") or b.get("username"), 254).lower(), b.get("password")
    if not isinstance(pw, str) or not ident:
        raise ApiError(400, "invalid_input", "Email and password are required")
    tkey = f"{request.remote_addr}|{ident}"
    throttle(tkey)
    admin_user = os.environ.get("ADMIN_USER", "ACEt").lower()
    if ident == admin_user:
        ph, pp = os.environ.get("ADMIN_PASSWORD_HASH"), os.environ.get("ADMIN_PASSWORD")
        ok = bool(ph and check_password_hash(ph, pw)) or bool(not ph and pp and hmac.compare_digest(pp, pw))
        if not ok:
            _fails.setdefault(tkey, []).append(time.time())
            raise ApiError(401, "bad_credentials", "Incorrect username or password")
        return jsonify(token=new_session("admin", None, "admin", admin=True), admin=True)
    ref = get(f"idx/email/{sha(ident)}.json")
    users = get(f"biz/{ref['bid']}/users.json", {}) if ref else {}
    u = users.get(ref["uid"]) if ref else None
    ok = check_password_hash(u["h"] if u else DUMMY, pw) and bool(u) and u.get("active", True)
    if not ok:
        _fails.setdefault(tkey, []).append(time.time())
        raise ApiError(401, "bad_credentials", "Email or password is not correct")
    g.bid, g.uid = ref["bid"], ref["uid"]
    prof = profile(ref["bid"], fresh=True)
    tok = new_session(ref["uid"], ref["bid"], u["role"], remember=bool(b.get("remember")))
    audit("login", "auth")
    return jsonify(token=tok, user=public_user(u, ref["uid"]), business=prof_out(prof))


def prof_out(p):
    o = {k: p.get(k) for k in ("id", "name", "type", "loc", "phone", "cur", "tax", "foot", "col", "mt", "plan", "status", "trial_ends")}
    if p.get("logo"):
        o["logo_url"] = file_url(p["id"], p["logo"])
    return o


@app.post("/api/v1/auth/logout")
@api()
def logout():
    kill_session(g.bid, g.sid)
    return jsonify(ok=True)


@app.get("/api/v1/auth/me")
@api()
def me():
    u = get(K("users.json"), {}).get(g.uid)
    return jsonify(user=public_user(u, g.uid), business=prof_out(g.prof), permissions=ROLES[g.role])


@app.get("/api/v1/auth/sessions")
@api()
def sessions():
    idx = get(K("sessions.json"), {})
    return jsonify(data=[{"id": k, "created": v["created"], "ip": v["ip"], "device": v["ua"], "current": k == g.sid}
                         for k, v in idx.items() if v["uid"] == g.uid and v["exp"] > time.time()])


@app.delete("/api/v1/auth/sessions/<sid>")
@api()
def end_session(sid):
    s = get(K("sessions.json"), {}).get(rid(sid))
    if not s or s["uid"] != g.uid:
        raise ApiError(404, "not_found", "Session not found")
    kill_session(g.bid, sid)
    return jsonify(ok=True)


@app.post("/api/v1/auth/password")
@api()
def change_password():
    b = body()
    check_password(b.get("new"))
    with lock("u" + g.bid):
        users = get(K("users.json"), {})
        u = users[g.uid]
        if not check_password_hash(u["h"], str(b.get("old", ""))):
            raise ApiError(400, "bad_credentials", "Current password is not correct")
        u["h"] = generate_password_hash(b["new"])
        put(K("users.json"), users)
    kill_user_sessions(g.bid, g.uid, keep=g.sid)
    audit("password_change", "auth")
    return jsonify(ok=True)


# ----------------------------------------------------------------------------- business profile, users, files
@app.get("/api/v1/business")
@api()
def business_get():
    return jsonify(prof_out(g.prof))


@app.patch("/api/v1/business")
@api()
def business_patch():
    need("settings.update")
    b, p = body(), dict(g.prof)
    old = prof_out(p)
    for k, f in (("name", s_), ("loc", s_), ("phone", lambda v: s_(v, 30)), ("foot", lambda v: s_(v, 300))):
        if k in b:
            p[k] = f(b[k])
    if "tax" in b:
        p["tax"] = min(n_(b["tax"]), 50)
    if "col" in b:
        if not re.match(r"^#[0-9a-fA-F]{6}$", str(b["col"])):
            raise ApiError(400, "invalid_input", "Invalid colour")
        p["col"] = b["col"]
    if "mt" in b:
        if b["mt"] not in (0, 1, 2):
            raise ApiError(400, "invalid_input", "Unknown template")
        p["mt"] = b["mt"]
    if not p["name"]:
        raise ApiError(400, "invalid_input", "Business name is required")
    save_profile(p)
    audit("update", "settings", g.bid, old, prof_out(p))
    return jsonify(prof_out(p))


def sniff(data):
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:5] == b"%PDF-":
        return "application/pdf"
    return None


def store_file(kind):
    f = request.files.get("file")
    if not f:
        raise ApiError(400, "no_file", "Attach a file")
    data = f.read()
    ctype = sniff(data)
    if not ctype or (kind == "logo" and not ctype.startswith("image/")):
        raise ApiError(400, "bad_file", "Allowed types: PNG, JPG, WebP" + ("" if kind == "logo" else ", PDF"))
    if kind == "logo" and len(data) > 1024 * 1024:
        raise ApiError(400, "too_large", "Logo must be under 1 MB")
    fid = uuid.uuid4().hex
    s3.put_object(Bucket=BUCKET, Key=K("files", fid), Body=data, ContentType=ctype)
    with lock("f" + g.bid):
        fl = get(K("files.json"), {})
        fl[fid] = {"name": re.sub(r"[^\w.\- ]", "_", s_(f.filename or "file", 100)), "type": ctype, "size": len(data),
                   "kind": kind, "by": g.uid, "at": iso(), "note": s_(request.form.get("note", ""), 200)}
        put(K("files.json"), fl)
    return fid, fl[fid]


def file_url(bid, fid, name=None):
    p = {"Bucket": BUCKET, "Key": f"biz/{bid}/files/{fid}"}
    if name:
        p["ResponseContentDisposition"] = f'attachment; filename="{name}"'
    return s3.generate_presigned_url("get_object", Params=p, ExpiresIn=300)


@app.post("/api/v1/business/logo")
@api()
def logo_set():
    need("settings.update")
    fid, _ = store_file("logo")
    p = dict(g.prof)
    old, p["logo"] = p.get("logo"), fid
    save_profile(p)
    if old:
        delete_file(old)
    audit("update", "logo", fid)
    return jsonify(prof_out(p))


@app.delete("/api/v1/business/logo")
@api()
def logo_del():
    need("settings.update")
    p = dict(g.prof)
    if p.get("logo"):
        delete_file(p["logo"])
        p["logo"] = None
        save_profile(p)
    return jsonify(prof_out(p))


def delete_file(fid):
    with lock("f" + g.bid):
        fl = get(K("files.json"), {})
        if fl.pop(fid, None):
            delete(K("files", fid))
            put(K("files.json"), fl)


@app.post("/api/v1/files")
@api()
def files_up():
    need("files.create")
    fid, meta = store_file("document")
    audit("upload", "files", fid)
    return jsonify(id=fid, **meta), 201


@app.get("/api/v1/files")
@api()
def files_list():
    need("files.read")
    return jsonify(data=[{"id": k, **v} for k, v in get(K("files.json"), {}).items() if v["kind"] == "document"])


@app.get("/api/v1/files/<fid>/url")
@api()
def files_url(fid):
    need("files.read")
    m = get(K("files.json"), {}).get(rid(fid))
    if not m:
        raise ApiError(404, "not_found", "File not found")
    return jsonify(url=file_url(g.bid, fid, m["name"]), expires_in=300)


@app.delete("/api/v1/files/<fid>")
@api()
def files_del(fid):
    need("files.delete")
    if rid(fid) not in get(K("files.json"), {}):
        raise ApiError(404, "not_found", "File not found")
    delete_file(fid)
    audit("delete", "files", fid)
    return jsonify(ok=True)


@app.get("/api/v1/users")
@api()
def users_list():
    need("users.read")
    return jsonify(data=[public_user(u, k) for k, u in get(K("users.json"), {}).items()])


@app.post("/api/v1/users")
@api()
def users_add():
    need("users.create")
    b = body()
    email, role = s_(b.get("email"), 254).lower(), b.get("role", "cashier")
    if role not in ("manager", "cashier") or not EMAIL_RE.match(email) or not s_(b.get("name")):
        raise ApiError(400, "invalid_input", "Name, valid email and role (manager or cashier) are required")
    check_password(b.get("password"))
    with lock("platform"), lock("u" + g.bid):
        users = get(K("users.json"), {})
        if len(users) >= plan_limit("max_users"):
            raise ApiError(402, "plan_limit", "User limit reached for your plan")
        if get(f"idx/email/{sha(email)}.json"):
            raise ApiError(409, "email_exists", "That email is already registered")
        uid = nid()
        users[uid] = {"name": s_(b["name"]), "email": email, "phone": s_(b.get("phone"), 30), "role": role, "active": True,
                      "h": generate_password_hash(b["password"]), "created": iso()}
        put(f"idx/email/{sha(email)}.json", {"bid": g.bid, "uid": uid})
        put(K("users.json"), users)
    audit("create", "users", uid, None, {"email": email, "role": role})
    return jsonify(public_user(users[uid], uid)), 201


@app.patch("/api/v1/users/<uid>")
@api()
def users_patch(uid):
    need("users.update")
    b = body()
    with lock("u" + g.bid):
        users = get(K("users.json"), {})
        u = users.get(rid(uid))
        if not u or u["role"] == "owner":
            raise ApiError(404, "not_found", "User not found")
        old = public_user(u, uid)
        if "role" in b:
            if b["role"] not in ("manager", "cashier"):
                raise ApiError(400, "invalid_input", "Invalid role")
            u["role"] = b["role"]
        if "active" in b:
            u["active"] = bool(b["active"])
        if b.get("password"):
            check_password(b["password"])
            u["h"] = generate_password_hash(b["password"])
        put(K("users.json"), users)
    kill_user_sessions(g.bid, uid)
    audit("update", "users", uid, old, public_user(u, uid))
    return jsonify(public_user(u, uid))


# ----------------------------------------------------------------------------- generic collections
COLL = {
    "items": dict(f={"n": s_, "sku": s_, "barcode": s_, "cat": s_, "c": n_, "p": n_, "st": on_, "reorder": n_}, req=("n", "sku", "p"), uniq="sku", search=("n", "sku", "barcode")),
    "customers": dict(f={"n": s_, "ph": s_, "em": s_, "notes": lambda v: s_(v, 1000)}, req=("n",), search=("n", "ph", "em")),
    "suppliers": dict(f={"n": s_, "ph": s_, "em": s_, "notes": lambda v: s_(v, 1000)}, req=("n",), search=("n", "ph", "em")),
    "expenses": dict(f={"date": d_, "cat": s_, "amt": n_, "note": s_}, req=("date", "amt"), search=("cat", "note")),
}


def coll_get(name):
    return get(K("c", name + ".json"), {})


def coll_put(name, data):
    put(K("c", name + ".json"), data)


def clean(spec, b, partial=False):
    out = {}
    for k, fn in spec["f"].items():
        if k in b:
            out[k] = fn(b[k])
    for k in spec["req"]:
        if not partial and out.get(k) in (None, ""):
            raise ApiError(400, "missing_field", f"'{k}' is required")
        if partial and k in out and out[k] in (None, ""):
            raise ApiError(400, "missing_field", f"'{k}' cannot be empty")
    return out


def page(rows, key=None):
    lim = max(1, min(int(request.args.get("limit", 50) or 50), 100))
    off = max(0, int(request.args.get("offset", 0) or 0))
    return jsonify(data=rows[off:off + lim], total=len(rows), limit=lim, offset=off)


@app.get("/api/v1/<any(items,customers,suppliers,expenses):cn>")
@api()
def c_list(cn):
    need(cn + ".read")
    spec, q = COLL[cn], request.args.get("q", "").strip().lower()
    rows = [{"id": k, **v} for k, v in coll_get(cn).items()]
    if q:
        rows = [r for r in rows if any(q in str(r.get(f, "")).lower() for f in spec["search"])]
    rows.sort(key=lambda r: (str(r.get("date", "")), str(r.get("n", "")).lower()), reverse=(cn == "expenses"))
    return page(rows)


@app.post("/api/v1/<any(items,customers,suppliers,expenses):cn>")
@api()
def c_add(cn):
    need(cn + ".create")
    spec, rec = COLL[cn], clean(COLL[cn], body())
    with lock(g.bid):
        data = coll_get(cn)
        if cn == "items":
            if len(data) >= plan_limit("max_items"):
                raise ApiError(402, "plan_limit", "Item limit reached for your plan")
            if any(v["sku"] == rec["sku"] for v in data.values()):
                raise ApiError(409, "duplicate", "That SKU already exists")
            rec.setdefault("c", 0)
        i = nid()
        rec["created"] = iso()
        data[i] = rec
        coll_put(cn, data)
    audit("create", cn, i, None, rec)
    return jsonify(id=i, **rec), 201


@app.get("/api/v1/<any(items,customers,suppliers,expenses):cn>/<rid_>")
@api()
def c_one(cn, rid_):
    need(cn + ".read")
    r = coll_get(cn).get(rid(rid_))
    if not r:
        raise ApiError(404, "not_found", "Record not found")
    return jsonify(id=rid_, **r)


@app.patch("/api/v1/<any(items,customers,suppliers,expenses):cn>/<rid_>")
@api()
def c_patch(cn, rid_):
    need(cn + ".update")
    spec, ch = COLL[cn], clean(COLL[cn], body(), partial=True)
    with lock(g.bid):
        data = coll_get(cn)
        r = data.get(rid(rid_))
        if not r:
            raise ApiError(404, "not_found", "Record not found")
        if "sku" in ch and any(v["sku"] == ch["sku"] for k, v in data.items() if k != rid_):
            raise ApiError(409, "duplicate", "That SKU already exists")
        old = dict(r)
        r.update(ch)
        coll_put(cn, data)
    audit("update", cn, rid_, old, r)
    return jsonify(id=rid_, **r)


@app.delete("/api/v1/<any(items,customers,suppliers,expenses):cn>/<rid_>")
@api()
def c_del(cn, rid_):
    need(cn + ".delete")
    with lock(g.bid):
        data = coll_get(cn)
        old = data.pop(rid(rid_), None)
        if not old:
            raise ApiError(404, "not_found", "Record not found")
        coll_put(cn, data)
    audit("delete", cn, rid_, old)
    return jsonify(ok=True)


# ----------------------------------------------------------------------------- sales
def sale_shard(month):
    if not re.match(r"^\d{6}$", month):
        raise ApiError(400, "invalid_month", "Use YYYYMM")
    return K("sales", month + ".json")


@app.post("/api/v1/sales")
@api()
def sale_create():
    need("sales.create")
    b, idem = body(), request.headers.get("Idempotency-Key", "")[:64]
    with lock(g.bid):
        meta = get(K("meta.json"), {"sale": 1000, "inv": 0, "idem": {}})
        if idem and idem in meta["idem"]:
            sid = meta["idem"][idem]
            return jsonify(get(sale_shard(sid[:6]), {})[sid]), 200
        items, custs = coll_get("items"), coll_get("customers")
        raw = b.get("items")
        if not isinstance(raw, list) or not raw or len(raw) > 200:
            raise ApiError(400, "invalid_input", "Add at least one item")
        lines, seen = [], {}
        for l in raw:
            iid, q = rid(str(l.get("i"))), n_(l.get("q"), 0.001)
            it = items.get(iid)
            if not it:
                raise ApiError(400, "unknown_item", "An item in the cart no longer exists")
            seen[iid] = seen.get(iid, 0) + q
            if it.get("st") is not None and it["st"] < seen[iid]:
                raise ApiError(409, "insufficient_stock", f"Not enough stock for {it['n']}")
            lines.append({"i": iid, "n": it["n"], "q": q, "p": it["p"], "c": it.get("c", 0)})
        cust, method = b.get("cust") or "", b.get("method", "Cash")
        if method not in METHODS:
            raise ApiError(400, "invalid_input", "Unknown payment method")
        if cust and cust not in custs:
            raise ApiError(400, "invalid_input", "Unknown customer")
        if method == "Credit" and not cust:
            raise ApiError(400, "invalid_input", "Choose a customer for credit sales")
        disc_pct = min(n_(b.get("disc", 0)), 100)
        sub = sum(l["q"] * l["p"] for l in lines)
        disc = sub * disc_pct / 100
        tax = (sub - disc) * g.prof["tax"] / 100
        meta["sale"] += 1
        month = ym()
        sid = f"{month}-{nid()}"
        sale = {"id": sid, "no": meta["sale"], "date": iso(), "cust": cust, "items": lines, "sub": round(sub, 2), "disc": round(disc, 2),
                "tax": round(tax, 2), "total": round(sub - disc + tax, 2), "method": method, "paid": method != "Credit",
                "status": "completed", "by": g.uid}
        shard = get(sale_shard(month), {})
        shard[sid] = sale
        put(sale_shard(month), shard)
        for iid, q in seen.items():
            if items[iid].get("st") is not None:
                items[iid]["st"] = round(items[iid]["st"] - q, 3)
        coll_put("items", items)
        if idem:
            meta["idem"][idem] = sid
            meta["idem"] = dict(list(meta["idem"].items())[-200:])
        put(K("meta.json"), meta)
    audit("create", "sales", sid, None, {"no": sale["no"], "total": sale["total"]})
    return jsonify(sale), 201


@app.get("/api/v1/sales")
@api()
def sale_list():
    need("sales.read")
    rows = sorted(get(sale_shard(request.args.get("month", ym())), {}).values(), key=lambda s: s["date"], reverse=True)
    return page(rows)


@app.get("/api/v1/sales/<sid>")
@api()
def sale_one(sid):
    need("sales.read")
    s = get(sale_shard(rid(sid)[:6]), {}).get(sid)
    if not s:
        raise ApiError(404, "not_found", "Sale not found")
    return jsonify(s)


@app.post("/api/v1/sales/<sid>/refund")
@api()
def sale_refund(sid):
    need("sales.refund")
    with lock(g.bid):
        key = sale_shard(rid(sid)[:6])
        shard = get(key, {})
        s = shard.get(sid)
        if not s or s["status"] == "refunded":
            raise ApiError(404, "not_found", "Sale not found or already refunded")
        s["status"], s["refunded_at"] = "refunded", iso()
        put(key, shard)
        items = coll_get("items")
        for l in s["items"]:
            if l["i"] in items and items[l["i"]].get("st") is not None:
                items[l["i"]]["st"] = round(items[l["i"]]["st"] + l["q"], 3)
        coll_put("items", items)
    audit("refund", "sales", sid)
    return jsonify(s)


# ----------------------------------------------------------------------------- invoices
@app.post("/api/v1/invoices")
@api()
def inv_create():
    need("invoices.create")
    b = body()
    with lock(g.bid):
        custs, items = coll_get("customers"), coll_get("items")
        if b.get("cust") not in custs:
            raise ApiError(400, "invalid_input", "Choose a customer")
        lines = []
        for l in (b.get("lines") or [])[:100]:
            if l.get("i"):
                it = items.get(rid(str(l["i"])))
                if not it:
                    raise ApiError(400, "unknown_item", "Unknown item")
                lines.append({"n": it["n"], "q": n_(l.get("q", 1), 0.001), "p": it["p"]})
            else:
                lines.append({"n": s_(l.get("n")), "q": n_(l.get("q", 1), 0.001), "p": n_(l.get("p"))})
        if not lines:
            raise ApiError(400, "invalid_input", "Add at least one line")
        sub = sum(l["q"] * l["p"] for l in lines)
        tax = sub * g.prof["tax"] / 100
        meta = get(K("meta.json"), {"sale": 1000, "inv": 0, "idem": {}})
        meta["inv"] += 1
        invs, i = coll_get("invoices"), nid()
        invs[i] = {"no": f"{meta['inv']:04d}", "cust": b["cust"], "date": now().date().isoformat(), "due": d_(b.get("due")),
                   "lines": lines, "tax": round(tax, 2), "total": round(sub + tax, 2), "payments": [], "paid": False, "created": iso()}
        coll_put("invoices", invs)
        put(K("meta.json"), meta)
    audit("create", "invoices", i, None, {"no": invs[i]["no"], "total": invs[i]["total"]})
    return jsonify(id=i, **invs[i]), 201


@app.get("/api/v1/invoices")
@api()
def inv_list():
    need("invoices.read")
    rows = sorted(({"id": k, **v} for k, v in coll_get("invoices").items()), key=lambda r: r["created"], reverse=True)
    st = request.args.get("status")
    if st:
        rows = [r for r in rows if (("paid" if r["paid"] else "overdue" if r["due"] < now().date().isoformat() else "unpaid") == st)]
    return page(rows)


@app.post("/api/v1/invoices/<iid>/payments")
@api()
def inv_pay(iid):
    need("invoices.update")
    b = body()
    with lock(g.bid):
        invs = coll_get("invoices")
        inv = invs.get(rid(iid))
        if not inv:
            raise ApiError(404, "not_found", "Invoice not found")
        due = round(inv["total"] - sum(p["amt"] for p in inv["payments"]), 2)
        amt = n_(b.get("amount", due), 0.01)
        method = b.get("method", "Cash")
        if method not in METHODS or method == "Credit":
            raise ApiError(400, "invalid_input", "Unknown payment method")
        if amt > due + 0.005:
            raise ApiError(400, "overpayment", "Payment is more than the balance")
        inv["payments"].append({"amt": amt, "method": method, "at": iso(), "ref": s_(b.get("ref"), 60), "by": g.uid})
        inv["paid"] = round(due - amt, 2) <= 0.005
        coll_put("invoices", invs)
    audit("payment", "invoices", iid, None, {"amt": amt})
    return jsonify(id=iid, **inv)


# ----------------------------------------------------------------------------- reports, export, audit, notifications
def months_between(a, b):
    y, m, out = int(a[:4]), int(a[4:]), []
    while f"{y}{m:02d}" <= b and len(out) < 12:
        out.append(f"{y}{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


@app.get("/api/v1/reports/summary")
@api()
def report():
    need("reports.read")
    to = request.args.get("to", ym())
    frm = request.args.get("from", to)
    sales, by_m, top, daily = [], {}, {}, {}
    for m in months_between(frm, to):
        sales += [s for s in get(sale_shard(m), {}).values() if s["status"] == "completed"]
    for s in sales:
        by_m[s["method"]] = round(by_m.get(s["method"], 0) + s["total"], 2)
        daily[s["date"][:10]] = round(daily.get(s["date"][:10], 0) + s["total"], 2)
        for l in s["items"]:
            top[l["n"]] = round(top.get(l["n"], 0) + l["q"] * l["p"], 2)
    lo, hi = f"{frm[:4]}-{frm[4:]}-01", f"{to[:4]}-{to[4:]}-31"
    exp = sum(e["amt"] for e in coll_get("expenses").values() if lo <= e["date"] <= hi)
    rev, cogs = sum(s["total"] for s in sales), sum(l["q"] * l["c"] for s in sales for l in s["items"])
    inv = coll_get("invoices")
    return jsonify(revenue=round(rev, 2), cogs=round(cogs, 2), expenses=round(exp, 2), profit=round(rev - cogs - exp, 2),
                   sales_count=len(sales), by_method=by_m, daily=dict(sorted(daily.items())),
                   top_items=sorted(({"n": k, "v": v} for k, v in top.items()), key=lambda x: -x["v"])[:10],
                   outstanding=round(sum(i["total"] - sum(p["amt"] for p in i["payments"]) for i in inv.values() if not i["paid"])
                                     + sum(s["total"] for s in sales if not s["paid"]), 2),
                   low_stock=[{"id": k, "n": v["n"], "st": v["st"]} for k, v in coll_get("items").items()
                              if v.get("st") is not None and v["st"] <= v.get("reorder", 5)])


def safe_cell(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in "=+-@\t\r" else v


@app.get("/api/v1/export/<any(items,customers,suppliers,expenses,invoices):cn>.csv")
@api()
def export(cn):
    need("export.read")
    data = coll_get(cn)
    rows = [{"id": k, **{a: b for a, b in v.items() if not isinstance(b, (list, dict))}} for k, v in data.items()]
    cols = sorted({c for r in rows for c in r}, key=lambda c: (c != "id", c))
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(cols)
    for r in rows:
        w.writerow([safe_cell(r.get(c)) for c in cols])
    audit("export", cn)
    return make_response(out.getvalue(), 200, {"Content-Type": "text/csv; charset=utf-8", "Content-Disposition": f"attachment; filename={cn}.csv"})


@app.get("/api/v1/audit")
@api()
def audit_list():
    need("audit.read")
    m = request.args.get("month", ym())
    if not re.match(r"^\d{6}$", m):
        raise ApiError(400, "invalid_month", "Use YYYYMM")
    return page(list(reversed(get(K("audit", m + ".json"), []))))


@app.get("/api/v1/announcements")
@api()
def announcements():
    return jsonify(data=get("platform/announcements.json", [])[-10:][::-1])


@app.post("/api/v1/support/tickets")
@api()
def ticket_new():
    need("tickets.create")
    b = body()
    t = {"id": nid(), "bid": g.bid, "business": g.prof["name"], "by": g.uid, "cat": s_(b.get("cat"), 40), "subject": s_(b.get("subject")),
         "text": s_(b.get("text"), 3000), "status": "open", "created": iso()}
    if not t["subject"] or not t["text"]:
        raise ApiError(400, "invalid_input", "Subject and description are required")
    with lock("tickets"):
        all_ = get("platform/tickets.json", [])
        all_.append(t)
        put("platform/tickets.json", all_)
    return jsonify(t), 201


@app.get("/api/v1/support/tickets")
@api()
def ticket_mine():
    need("tickets.read")
    return jsonify(data=[t for t in get("platform/tickets.json", []) if t["bid"] == g.bid][::-1])


# ----------------------------------------------------------------------------- platform admin
@app.get("/api/v1/admin/businesses")
@api(admin=True)
def adm_biz():
    q, st = request.args.get("q", "").lower(), request.args.get("status")
    rows = [{"id": k, **v} for k, v in get("platform/businesses.json", {}).items()]
    rows = [r for r in rows if (not q or q in json.dumps(r).lower()) and (not st or r["status"] == st)]
    return page(sorted(rows, key=lambda r: r["created"], reverse=True))


@app.patch("/api/v1/admin/businesses/<bid>")
@api(admin=True)
def adm_biz_patch(bid):
    b = body()
    p = get(f"biz/{rid(bid)}/profile.json")
    if not p:
        raise ApiError(404, "not_found", "Business not found")
    g.bid, g.uid = bid, "admin"
    if "status" in b:
        if b["status"] not in ("trial", "active", "past_due", "suspended", "cancelled", "expired"):
            raise ApiError(400, "invalid_input", "Unknown status")
        p["status"] = b["status"]
    if "plan" in b:
        if b["plan"] not in get("platform/plans.json", DEFAULT_PLANS):
            raise ApiError(400, "invalid_input", "Unknown plan")
        p["plan"] = b["plan"]
    save_profile(p)
    audit("admin_update", "businesses", bid, None, {k: b[k] for k in ("status", "plan") if k in b})
    return jsonify(prof_out(p))


@app.get("/api/v1/admin/plans")
@api(admin=True)
def adm_plans():
    return jsonify(get("platform/plans.json", DEFAULT_PLANS))


@app.put("/api/v1/admin/plans")
@api(admin=True)
def adm_plans_put():
    b = body()
    plans = {}
    for name, lim in b.items():
        plans[s_(name, 30)] = {"max_users": int(n_(lim.get("max_users"))), "max_items": int(n_(lim.get("max_items")))}
    put("platform/plans.json", plans)
    return jsonify(plans)


@app.post("/api/v1/admin/announcements")
@api(admin=True)
def adm_ann():
    b = body()
    text = s_(b.get("text"), 500)
    if not text:
        raise ApiError(400, "invalid_input", "Write a message")
    with lock("platform"):
        a = get("platform/announcements.json", [])
        a.append({"id": nid(), "text": text, "at": iso()})
        put("platform/announcements.json", a[-50:])
    return jsonify(ok=True), 201


@app.get("/api/v1/admin/tickets")
@api(admin=True)
def adm_tickets():
    return page(get("platform/tickets.json", [])[::-1])


@app.patch("/api/v1/admin/tickets/<tid>")
@api(admin=True)
def adm_ticket(tid):
    st = body().get("status")
    if st not in ("open", "in_progress", "waiting", "resolved", "closed"):
        raise ApiError(400, "invalid_input", "Unknown status")
    with lock("tickets"):
        all_ = get("platform/tickets.json", [])
        t = next((x for x in all_ if x["id"] == rid(tid)), None)
        if not t:
            raise ApiError(404, "not_found", "Ticket not found")
        t["status"] = st
        put("platform/tickets.json", all_)
    return jsonify(t)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
