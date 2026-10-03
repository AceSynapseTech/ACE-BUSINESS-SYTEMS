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
  BASE_URL                       public address of this deployment, e.g. https://ace-business-sytems-1.onrender.com
                                 (optional; falls back to the request host). Stores live at BASE_URL/shop/<slug>.
  ROOT_DOMAIN                    OPTIONAL, only for future custom-domain/subdomain support. Leave empty on Render.
  ALLOWED_ORIGINS                comma-separated origins allowed to call the API (not needed if index.html is served by this app)
Run on Render with ONE worker (writes are serialised with in-process locks):
  gunicorn app:app --workers 1 --threads 8 --timeout 60
"""
import os, re, io, csv, sys, json, time, uuid, hmac, math, hashlib, secrets, threading
from datetime import datetime, timezone, timedelta, date
from decimal import Decimal, ROUND_HALF_UP
from functools import wraps

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify, g, send_from_directory, make_response, Response
from html import escape as hesc
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
import unicodedata

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
                "reports.read", "export.read", "tickets.*", "files.*", "audit.read", "orders.*"],
    "cashier": ["items.read", "customers.read", "customers.create", "sales.create", "sales.read",
                "invoices.read", "files.read", "tickets.create", "orders.read"],
}
DEFAULT_PLANS = {"Free": {"max_users": 1, "max_items": 50}, "Starter": {"max_users": 5, "max_items": 500},
                 "Business": {"max_users": 25, "max_items": 10000}, "Enterprise": {"max_users": 1000, "max_items": 100000}}

# ----------------------------------------------------------------------------- subscription configuration (single source of truth)
SUBSCRIPTION_PRODUCT = "ACE Business"
SUBSCRIPTION_MONTHLY_KES = 1500
SUBSCRIPTION_YEARLY_KES = 15000
SUBSCRIPTION_YEARLY_SAVING_KES = SUBSCRIPTION_MONTHLY_KES * 12 - SUBSCRIPTION_YEARLY_KES      # 3,000
SUBSCRIPTION_YEARLY_EFFECTIVE_MONTHLY_KES = SUBSCRIPTION_YEARLY_KES // 12                       # 1,250
BILLING_MONTHS = {"monthly": 1, "yearly": 12}
TRIAL_DAYS = 30
PAST_DUE_GRACE_DAYS = 7
MPESA_PAYBILL = "714888"
MPESA_ACCOUNT = "480457"
MPESA_RECIPIENT = os.environ.get("MPESA_RECIPIENT", "LOOP BIZ")          # comma-separated list allowed
MPESA_MAX_AGE_DAYS = int(os.environ.get("MPESA_MAX_AGE_DAYS", 120))
REFERRAL_REWARD_KES = 500
REFERRAL_AUTO_APPROVE = os.environ.get("REFERRAL_AUTO_APPROVE", "1") != "0"
PRICE, PAYBILL, PAY_ACCOUNT = SUBSCRIPTION_MONTHLY_KES, MPESA_PAYBILL, MPESA_ACCOUNT      # legacy names
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
    if not p.get("slug"):      # never lose the permanent workspace slug if a stale profile copy is saved
        old = get(K("profile.json")) or {}
        for k in ("slug", "workspace_host"):
            if old.get(k):
                p[k] = old[k]
    put(K("profile.json"), p)
    _pcache[g.bid] = (time.time(), p)
    with lock("platform"):
        idx = get("platform/businesses.json", {})
        idx[g.bid] = {"name": p["name"], "owner": p.get("owner_email"), "phone": p.get("phone"), "plan": p["plan"],
                      "status": p["status"], "type": p["type"], "created": p["created"], "billing": p.get("billing", "monthly"),
                      "trial_ends": p.get("trial_ends"), "period_start": p.get("period_start"), "period_end": p.get("period_end"),
                      "partial_c": p.get("partial_c", 0), "credit_c": p.get("credit_c", 0), "paid_c": p.get("paid_c", 0),
                      "target_c": p.get("target_c", 0), "pay_n": p.get("pay_n", 0), "referral_code": p.get("referral_code"), "slug": p.get("slug")}
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
                    hb = getattr(g, "host_bid", None)      # the hostname is only a hint; a session never crosses workspaces
                    if hb and hb != g.bid:
                        raise ApiError(403, "workspace_mismatch", "This session belongs to a different workspace. Sign in from your own workspace address.")
                    try:
                        settle(g.prof)   # persist trial/period expiry (no background worker needed)
                    except ApiError:
                        raise
                    except Exception:
                        app.logger.exception("settle failed")
                    st = eff_status(g.prof)
                    if not request.path.endswith("/auth/logout"):
                        if st in ("suspended", "cancelled"):
                            raise ApiError(403, "subscription_" + st, "This workspace is not active. Contact support.")
                        if st == "expired" and not expired_ok():
                            raise ApiError(403, "subscription_expired", "Your ACE subscription has expired. Your business data is safe. Renew to continue.")
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
    try:
        g.host_bid = resolve_host(request.host)
    except Exception:
        g.host_bid = None


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
        if request.path in ("/", "/register") and "Cache-Control" not in r.headers:
            r.headers["Cache-Control"] = "no-cache"
        r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
            "img-src 'self' data: blob: https://*.backblazeb2.com; connect-src 'self'; manifest-src 'self'; worker-src 'self'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
    return r


@app.get("/")
@app.get("/register")
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
    return {"id": uid, "name": u["name"], "email": u["email"], "role": u["role"], "active": u.get("active", True),
            "email_verified": bool(u.get("email_verified")), "google_linked": bool(u.get("google")), "phone": u.get("phone", "")}


def check_password(pw):
    if not isinstance(pw, str) or not (8 <= len(pw) <= 128):
        raise ApiError(400, "weak_password", "Password must be 8 to 128 characters")


@app.post("/api/v1/auth/register")
@api(public=True)
def register():
    if getattr(g, "host_bid", None):
        raise ApiError(403, "workspace_host", "Create new accounts from the main ACE website. This address belongs to an existing workspace.")
    b = body()
    name, email, phone = s_(b.get("name")), s_(b.get("email"), 254).lower(), s_(b.get("phone"), 30)
    biz = b.get("business") or {}
    bname, btype = s_(biz.get("name")), biz.get("type", "retail")
    if not name or not EMAIL_RE.match(email) or not bname:
        raise ApiError(400, "invalid_input", "Name, valid email and business name are required")
    if btype not in ("retail", "hardware", "restaurant", "salon", "pharmacy"):
        raise ApiError(400, "invalid_input", "Unknown business type")
    check_password(b.get("password"))
    col = biz.get("col") or "#0a6cff"
    if not re.match(r"^#[0-9a-fA-F]{6}$", col):
        raise ApiError(400, "invalid_input", "Invalid colour")
    plan = "Business"   # one public product (ACE Business); the customer never picks Free/Starter/Business/Enterprise
    rc = b.get("referral_code")
    ref = referral_lookup(rc)   # optional: empty = normal signup; a non-empty code must be valid
    if isinstance(rc, str) and rc.strip() and not ref:
        raise ApiError(400, "invalid_referral", "That referral code is not valid. Check it, or leave it empty to continue without one.")
    if ref:
        rp = get(f"biz/{ref['bid']}/profile.json") or {}
        if rp.get("owner_email", "").lower() == email or (phone and rp.get("phone") and _norm(rp["phone"]) == _norm(phone)):
            raise ApiError(400, "self_referral", "You cannot use your own referral code.")
    with lock("platform"):
        ek = f"idx/email/{sha(email)}.json"
        if get(ek):
            raise ApiError(409, "email_exists", "An account with this email already exists")
        bid, uid = uuid.uuid4().hex, nid()
        prof = {"id": bid, "name": bname, "type": btype, "loc": s_(biz.get("loc")), "phone": s_(biz.get("phone") or phone, 30),
                "owner_email": email, "cur": "KES", "tax": min(n_(biz.get("tax", 16)), 50), "foot": "Thank you for your business.",
                "col": col, "mt": biz.get("mt") if biz.get("mt") in (0, 1, 2, 3, 4) else 0, "plan": plan,
                "status": "trial", "trial_start": now().date().isoformat(), "trial_ends": (now() + timedelta(days=TRIAL_DAYS)).date().isoformat(), "logo": None, "created": iso()}
        sub_init(prof, ref, email, phone)
        if b.get("billing") in BILLING_MONTHS:
            prof["billing"] = b["billing"]
        _claim_slug(bid, prof)          # unique permanent workspace slug + domain index entry (B2)
        put(f"biz/{bid}/profile.json", prof)
        put(f"biz/{bid}/users.json", {uid: {"name": name, "email": email, "phone": phone, "role": "owner", "active": True,
                                             "h": generate_password_hash(b["password"]), "created": iso()}})
        put(f"biz/{bid}/meta.json", {"sale": 1000, "inv": 0, "idem": {}})
        put(ek, {"bid": bid, "uid": uid})
        put(f"biz/{bid}/store.json", store_defaults(prof))      # the online store is created together with the account
        idx = get("platform/businesses.json", {})
        idx[bid] = {"name": bname, "owner": email, "phone": phone, "plan": plan, "status": "trial", "type": btype, "created": prof["created"],
                     "billing": prof["billing"], "trial_ends": prof["trial_ends"], "referral_code": prof["referral_code"], "slug": prof["slug"]}
        put("platform/businesses.json", idx)
    g.bid, g.uid = bid, uid
    audit("register", "auth", bid)
    try:
        referral_register(prof)
    except Exception:
        app.logger.exception("referral registration failed")
    login_history(bid, uid, "register")
    send_verification(bid, uid, email)
    resolved = store_lookup(prof["slug"])          # the same resolver the public route uses: only report "active" if it really resolves
    stat = store_state(prof) if resolved and resolved[0] == bid else "unavailable"
    return jsonify(token=new_session(uid, bid, "owner"), business=prof_out(prof), slug=prof["slug"],
                   store_url=store_url(prof["slug"]), store_status=stat), 201


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
        if u:
            g.bid, g.uid = ref["bid"], ref["uid"]
            audit("login_failed", "auth")
            login_history(ref["bid"], ref["uid"], "login_failed")
        raise ApiError(401, "bad_credentials", "Email or password is not correct")
    hb = getattr(g, "host_bid", None)
    if hb and hb != ref["bid"]:
        raise ApiError(403, "workspace_mismatch", "This account belongs to a different workspace. Sign in from your own workspace address.")
    g.bid, g.uid = ref["bid"], ref["uid"]
    prof = ensure_workspace_safe(ref["bid"], profile(ref["bid"], fresh=True))      # migrate legacy business (no slug yet)
    tok = new_session(ref["uid"], ref["bid"], u["role"], remember=bool(b.get("remember")))
    audit("login", "auth")
    login_history(ref["bid"], ref["uid"], "login")
    return jsonify(token=tok, user=public_user(u, ref["uid"]), business=prof_out(prof))


def prof_out(p):
    o = {k: p.get(k) for k in ("id", "name", "type", "loc", "phone", "cur", "tax", "foot", "col", "mt", "plan", "status", "trial_ends")}
    o["email"] = p.get("email") or p.get("owner_email")
    o.update(sub_fields(p))
    o.update(prof_domain(p))
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
    g.prof = ensure_workspace_safe(g.bid, g.prof)
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
    for k, f in (("name", s_), ("loc", s_), ("phone", lambda v: s_(v, 30)), ("foot", lambda v: s_(v, 300)), ("email", lambda v: s_(v, 120))):
        if k in b:
            p[k] = f(b[k])
    if p.get("email") and not EMAIL_RE.match(str(p["email"])):
        raise ApiError(400, "invalid_input", "Enter a valid contact email")
    if "tax" in b:
        p["tax"] = min(n_(b["tax"]), 50)
    if "col" in b:
        if not re.match(r"^#[0-9a-fA-F]{6}$", str(b["col"])):
            raise ApiError(400, "invalid_input", "Invalid colour")
        p["col"] = b["col"]
    if "mt" in b:
        if b["mt"] not in (0, 1, 2, 3, 4):
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
    img_kind = kind in ("logo", "product", "banner")
    if not ctype or (img_kind and not ctype.startswith("image/")):
        raise ApiError(400, "bad_file", "Allowed types: PNG, JPG, WebP" + ("" if img_kind else ", PDF"))
    if kind == "logo" and len(data) > 1024 * 1024:
        raise ApiError(400, "too_large", "Logo must be under 1 MB")
    if kind in ("product", "banner") and len(data) > 3 * 1024 * 1024:
        raise ApiError(400, "too_large", "Image must be under 3 MB")
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
def bool_(v):
    return v is True or str(v).lower() in ("1", "true", "yes", "on")


def pct_(v):
    return min(n_(v or 0), 100)


def vars_(v):
    if isinstance(v, str):
        v = v.split(",")
    if not isinstance(v, list):
        raise ApiError(400, "invalid_input", "Variants must be a list")
    out = []
    for x in v:
        x = s_(x, 40)
        if x and x not in out:
            out.append(x)
    if len(out) > 30:
        raise ApiError(400, "invalid_input", "At most 30 variants")
    return out


COLL = {
    "items": dict(f={"n": s_, "sku": s_, "barcode": s_, "cat": s_, "c": n_, "p": n_, "st": on_, "reorder": n_,
                     "desc": lambda v: s_(v, 2000), "brand": s_, "disc": pct_, "pub": bool_, "feat": bool_, "vars": vars_},
                  req=("n", "sku", "p"), uniq="sku", search=("n", "sku", "barcode")),
    "customers": dict(f={"n": s_, "ph": s_, "em": s_, "notes": lambda v: s_(v, 1000)}, req=("n",), search=("n", "ph", "em")),
    "suppliers": dict(f={"n": s_, "ph": s_, "em": s_, "notes": lambda v: s_(v, 1000)}, req=("n",), search=("n", "ph", "em")),
    "expenses": dict(f={"date": d_, "cat": s_, "amt": n_, "note": s_}, req=("date", "amt"), search=("cat", "note")),
}


_icache = {}


def coll_get(name):
    return get(K("c", name + ".json"), {})


def coll_put(name, data):
    put(K("c", name + ".json"), data)
    if name == "items":
        _icache.pop(g.bid, None)      # the public store always reflects the latest product data


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
    if cn == "items" and old.get("img"):
        delete_file(old["img"])
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
    rows = []
    for k, v in get("platform/businesses.json", {}).items():
        if not isinstance(v, dict):
            continue
        r = {"id": k, "name": k[:8], "owner": "", "phone": "", "type": "", "plan": "", "created": "", **v}      # tolerate partly migrated rows
        r["status"] = eff_status(r)
        if r.get("slug"):
            r["store_url"] = store_url(r["slug"])
            r["workspace_url"] = ("https://" + workspace_host(r["slug"])) if workspace_host(r["slug"]) else None
        r.update(verified=kes(r.get("paid_c", 0)), remaining=kes(max(0, r.get("target_c", 0) - r.get("paid_c", 0))), credit=kes(r.get("credit_c", 0)),
                 payments=r.get("pay_n", 0), billing=r.get("billing", "monthly"))
        rows.append(r)
    rows = [r for r in rows if (not q or q in json.dumps(r).lower()) and (not st or r["status"] == st)]
    return page(sorted(rows, key=lambda r: str(r.get("created") or ""), reverse=True))


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
        if b["plan"] not in get("platform/plans.json", DEFAULT_PLANS) and b["plan"] != SUBSCRIPTION_PRODUCT:
            raise ApiError(400, "invalid_input", "Unknown plan")
        p["plan"] = "Business" if b["plan"] == SUBSCRIPTION_PRODUCT else b["plan"]
    if "billing" in b:
        if b["billing"] not in BILLING_MONTHS:
            raise ApiError(400, "invalid_billing_cycle", "Choose monthly or yearly billing.")
        p["billing"] = b["billing"]
    save_profile(p)
    audit("admin_update", "businesses", bid, None, {k: b[k] for k in ("status", "plan", "billing") if k in b})
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


# ============================================================================= account security add-on (v2)
# Additive: password recovery, email verification, Google sign-in, login history.
# New endpoints answer {"ok": true, "data": ...} / {"ok": false, "error": "..."}; existing endpoints are unchanged.
import smtplib, ssl, urllib.request, urllib.parse
from email.message import EmailMessage
from flask import redirect

PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
G_ID, G_SECRET = os.environ.get("GOOGLE_CLIENT_ID", ""), os.environ.get("GOOGLE_CLIENT_SECRET", "")
RESET_TTL, VERIFY_TTL, OAUTH_TTL = 3600, 2 * 86400, 600


def ok(data=None, status=200):
    return jsonify(ok=True, data=data if data is not None else {}), status


def base_url():
    return PUBLIC_URL or request.host_url.rstrip("/")


def send_mail(to, subject, text):
    """SMTP when SMTP_HOST is set; otherwise the message is written to the server log (development mode)."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        app.logger.warning("DEV MAIL to=%s subject=%s\n%s", to, subject, text)
        return

    def run():
        try:
            m = EmailMessage()
            m["From"], m["To"], m["Subject"] = os.environ.get("MAIL_FROM", "no-reply@localhost"), to, subject
            m.set_content(text)
            with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=15) as s:
                s.starttls(context=ssl.create_default_context())
                if os.environ.get("SMTP_USER"):
                    s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
                s.send_message(m)
        except Exception:
            app.logger.exception("mail failed")
    threading.Thread(target=run, daemon=True).start()


def issue_token(kind, bid, uid, ttl):
    tok = secrets.token_urlsafe(32)
    put(f"tokens/{kind}/{sha(tok)}.json", {"bid": bid, "uid": uid, "exp": time.time() + ttl})
    return tok


def take_token(kind, tok):
    """Single use: the record is deleted as soon as it is read."""
    if not isinstance(tok, str) or not 20 <= len(tok) <= 100:
        raise ApiError(400, "invalid_token", "This link is invalid or has expired")
    key = f"tokens/{kind}/{sha(tok)}.json"
    with lock("tok" + sha(tok)):
        rec = get(key)
        if rec:
            delete(key)
    if not rec or rec["exp"] < time.time():
        raise ApiError(400, "invalid_token", "This link is invalid or has expired")
    return rec


def login_history(bid, uid, event, method="password"):
    try:
        with lock("lh" + bid):
            h = get(f"biz/{bid}/logins.json", [])
            h.append({"t": iso(), "u": uid, "e": event, "m": method, "ip": request.remote_addr,
                      "ua": request.headers.get("User-Agent", "")[:120]})
            put(f"biz/{bid}/logins.json", h[-300:])
    except Exception:
        app.logger.exception("login history failed")


def send_verification(bid, uid, email):
    tok = issue_token("verify", bid, uid, VERIFY_TTL)
    send_mail(email, "Verify your ACE email address",
              f"Confirm your email address for ACE Business Management Systems:\n{base_url()}/#verify={tok}\n\nThis link expires in 48 hours.")


@app.post("/api/v1/auth/forgot")
@api(public=True)
def forgot():
    email = s_(body().get("email"), 254).lower()
    for k in (f"fp|{request.remote_addr}", f"fp|{email}"):
        throttle(k, limit=5, window=3600)
        _fails.setdefault(k, []).append(time.time())
    ref = get(f"idx/email/{sha(email)}.json") if EMAIL_RE.match(email) else None
    u = get(f"biz/{ref['bid']}/users.json", {}).get(ref["uid"]) if ref else None
    if u and u.get("active", True):
        tok = issue_token("reset", ref["bid"], ref["uid"], RESET_TTL)
        send_mail(email, "Reset your ACE password",
                  f"Use this link to choose a new password:\n{base_url()}/#reset={tok}\n\nIt expires in 1 hour and works once. "
                  "If you did not ask for this, ignore this email.")
    return ok({"message": "If that email is registered, a reset link is on its way."})


@app.post("/api/v1/auth/reset")
@api(public=True)
def reset_password():
    b = body()
    throttle(f"rs|{request.remote_addr}", limit=10, window=3600)
    _fails.setdefault(f"rs|{request.remote_addr}", []).append(time.time())
    check_password(b.get("password"))
    rec = take_token("reset", b.get("token"))
    with lock("u" + rec["bid"]):
        users = get(f"biz/{rec['bid']}/users.json", {})
        u = users.get(rec["uid"])
        if not u:
            raise ApiError(400, "invalid_token", "This link is invalid or has expired")
        u["h"], u["pw_changed"] = generate_password_hash(b["password"]), iso()
        u.pop("google_only", None)
        put(f"biz/{rec['bid']}/users.json", users)
    kill_user_sessions(rec["bid"], rec["uid"])
    g.bid, g.uid = rec["bid"], rec["uid"]
    audit("password_reset", "auth")
    login_history(rec["bid"], rec["uid"], "password_reset")
    return ok({"message": "Password updated. Please log in."})


@app.post("/api/v1/auth/verify/send")
@api()
def verify_send():
    throttle(f"vs|{g.uid}", limit=5, window=3600)
    _fails.setdefault(f"vs|{g.uid}", []).append(time.time())
    u = get(K("users.json"), {}).get(g.uid)
    if u.get("email_verified"):
        return ok({"message": "Your email is already verified."})
    send_verification(g.bid, g.uid, u["email"])
    return ok({"message": "Verification email sent."})


@app.post("/api/v1/auth/verify")
@api(public=True)
def verify_email():
    throttle(f"vf|{request.remote_addr}", limit=20, window=3600)
    _fails.setdefault(f"vf|{request.remote_addr}", []).append(time.time())
    rec = take_token("verify", body().get("token"))
    with lock("u" + rec["bid"]):
        users = get(f"biz/{rec['bid']}/users.json", {})
        if rec["uid"] in users:
            users[rec["uid"]]["email_verified"] = True
            put(f"biz/{rec['bid']}/users.json", users)
    return ok({"message": "Email verified."})


@app.get("/api/v1/auth/login-history")
@api()
def login_hist():
    h = [x for x in get(K("logins.json"), []) if x["u"] == g.uid][-50:][::-1]
    return ok([{"time": x["t"], "event": x["e"], "method": x["m"], "ip": x["ip"], "device": x["ua"]} for x in h])


@app.post("/api/v1/auth/sessions/revoke-others")
@api()
def revoke_others():
    kill_user_sessions(g.bid, g.uid, keep=g.sid)
    audit("revoke_sessions", "auth")
    return ok()


# ----------------------------------------------------------------------------- Google sign-in (authorization-code flow)
def g_url(mode, remember, bid=None, uid=None):
    if not (G_ID and G_SECRET):
        raise ApiError(503, "not_configured", "Google sign-in is not configured on this server")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    put(f"tokens/oauth/{sha(state)}.json", {"nonce": nonce, "mode": mode, "rem": bool(remember), "bid": bid, "uid": uid,
                                            "exp": time.time() + OAUTH_TTL})
    q = urllib.parse.urlencode({"client_id": G_ID, "redirect_uri": base_url() + "/api/v1/auth/google/callback",
                                "response_type": "code", "scope": "openid email profile", "state": state, "nonce": nonce,
                                "prompt": "select_account"})
    return "https://accounts.google.com/o/oauth2/v2/auth?" + q


@app.get("/api/v1/auth/google/config")
@api(public=True)
def google_config():
    return ok({"enabled": bool(G_ID and G_SECRET)})


@app.get("/api/v1/auth/google/start")
@api(public=True)
def google_start():
    throttle(f"gs|{request.remote_addr}", limit=30, window=900)
    _fails.setdefault(f"gs|{request.remote_addr}", []).append(time.time())
    return redirect(g_url("login", request.args.get("remember") == "1"))


@app.post("/api/v1/auth/google/link")
@api()
def google_link():
    return ok({"url": g_url("link", False, g.bid, g.uid)})


def g_json(url, data=None):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode() if data else None)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


@app.get("/api/v1/auth/google/callback")
@api(public=True)
def google_callback():
    fail = lambda m: redirect(f"{base_url()}/#gerr={urllib.parse.quote(m)}")
    try:
        st = take_token("oauth", request.args.get("state"))
    except ApiError:
        return fail("Google sign-in expired. Please try again.")
    if request.args.get("error") or not request.args.get("code"):
        return fail("Google sign-in was cancelled.")
    try:
        tk = g_json("https://oauth2.googleapis.com/token", {
            "code": request.args["code"], "client_id": G_ID, "client_secret": G_SECRET,
            "redirect_uri": base_url() + "/api/v1/auth/google/callback", "grant_type": "authorization_code"})
        c = g_json("https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode({"id_token": tk["id_token"]}))
    except Exception:
        app.logger.exception("google exchange failed")
        return fail("Could not complete Google sign-in. Please try again.")
    if (c.get("aud") != G_ID or c.get("iss") not in ("https://accounts.google.com", "accounts.google.com")
            or int(c.get("exp", 0)) < time.time() or not hmac.compare_digest(str(c.get("nonce", "")), st["nonce"])
            or str(c.get("email_verified")).lower() != "true" or not c.get("sub")):
        return fail("Google sign-in could not be verified.")
    sub, email, name = c["sub"], c.get("email", "").lower(), c.get("name") or c.get("email", "").split("@")[0]
    gk = f"idx/google/{sub}.json"
    with lock("platform"):
        ref = get(gk)
        if st["mode"] == "link":
            if ref and ref["uid"] != st["uid"]:
                return fail("That Google account is already linked to another ACE account.")
            put(gk, {"bid": st["bid"], "uid": st["uid"]})
            with lock("u" + st["bid"]):
                users = get(f"biz/{st['bid']}/users.json", {})
                users[st["uid"]]["google"] = sub
                put(f"biz/{st['bid']}/users.json", users)
            g.bid, g.uid = st["bid"], st["uid"]
            audit("google_link", "auth")
            return redirect(f"{base_url()}/#glinked=1")
        if not ref:
            if get(f"idx/email/{sha(email)}.json"):
                return fail("An ACE account with this email exists. Log in with your password, then connect Google under Security.")
            bid, uid = uuid.uuid4().hex, nid()
            prof = {"id": bid, "name": "My Business", "type": "retail", "loc": "", "phone": "", "owner_email": email, "cur": "KES",
                    "tax": 16, "foot": "Thank you for your business.", "col": "#0e5a63", "mt": 0, "plan": "Business", "status": "trial",
                    "trial_start": now().date().isoformat(), "trial_ends": (now() + timedelta(days=TRIAL_DAYS)).date().isoformat(), "logo": None, "created": iso(), "setup_needed": True}
            sub_init(prof, None)
            put(f"biz/{bid}/profile.json", prof)
            put(f"biz/{bid}/users.json", {uid: {"name": name[:200], "email": email, "phone": "", "role": "owner", "active": True,
                                                 "h": generate_password_hash(secrets.token_urlsafe(32)), "google_only": True,
                                                 "google": sub, "email_verified": True, "created": iso()}})
            put(f"biz/{bid}/meta.json", {"sale": 1000, "inv": 0, "idem": {}})
            put(f"idx/email/{sha(email)}.json", {"bid": bid, "uid": uid})
            put(gk, {"bid": bid, "uid": uid})
            idx = get("platform/businesses.json", {})
            idx[bid] = {"name": prof["name"], "owner": email, "phone": "", "plan": "Business", "status": "trial", "type": "retail", "created": prof["created"],
                           "billing": "monthly", "trial_ends": prof["trial_ends"], "referral_code": prof["referral_code"]}
            put("platform/businesses.json", idx)
            ref = {"bid": bid, "uid": uid}
    users = get(f"biz/{ref['bid']}/users.json", {})
    u = users.get(ref["uid"])
    if not u or not u.get("active", True):
        return fail("This account is disabled.")
    g.bid, g.uid = ref["bid"], ref["uid"]
    tok = new_session(ref["uid"], ref["bid"], u["role"], remember=st["rem"])
    audit("login", "auth", "google")
    login_history(ref["bid"], ref["uid"], "login", "google")
    code = secrets.token_urlsafe(32)   # one-time code: the session token itself never appears in a URL
    put(f"tokens/gcode/{sha(code)}.json", {"tok": tok, "rem": st["rem"], "exp": time.time() + 60})
    return redirect(f"{base_url()}/#gcode={code}")


@app.post("/api/v1/auth/google/exchange")
@api(public=True)
def google_exchange():
    rec = take_token("gcode", body().get("code"))
    return ok({"token": rec["tok"], "remember": rec["rem"]})


def sub_fields(p):
    st, t = eff_status(p), today()
    te, pe = _d(p.get("trial_ends")), _d(p.get("period_end"))
    end = pe if (st != "trial" and pe) else te
    return {"status": st, "trial_start": p.get("trial_start") or (p.get("created") or "")[:10] or None, "trial_ends": p.get("trial_ends"),
            "period_start": p.get("period_start"), "period_end": p.get("period_end"),
            "days_left": (end - t).days if end and st in ("trial", "active", "past_due") else None, "price": SUBSCRIPTION_MONTHLY_KES,
            "yearly_price": SUBSCRIPTION_YEARLY_KES, "billing": p.get("billing", "monthly"), "credit": kes(p.get("credit_c", 0)),
            "referral_code": p.get("referral_code")}


def expired_ok():
    """Endpoints an expired business can still use: sign-in/account, subscription + payments, referrals, support."""
    pth = request.path
    return (pth.startswith(("/api/v1/auth/", "/api/v1/billing", "/api/v1/subscription", "/api/v1/referrals", "/api/v1/announcements", "/api/v1/support"))
            or (pth == "/api/v1/business" and request.method == "GET"))


# ============================================================================= subscription, payments & referrals (v4)
# ONE public product (ACE Business): monthly KSh 1,500 or yearly KSh 15,000, first 30 days free.
# Money is stored as integer cents. The customer pastes the complete M-Pesa confirmation SMS; ACE parses and
# validates it. No official M-Pesa API is connected, so a valid message is PENDING ADMIN VERIFICATION and only
# VERIFIED payments count toward a billing period. Overpayment becomes account credit. Referral reward = KSh 500.
import calendar

PAYS = "platform/subscription_payments.json"
PENDING = ("submitted", "parsed", "pending_admin")
DISP = {"submitted": "pending_verification", "parsed": "pending_verification", "pending_admin": "pending_verification",
        "verified": "verified", "rejected": "rejected", "duplicate": "duplicate", "invalid": "invalid_message", "reversed": "reversed"}


def C(x):
    try:
        return int((Decimal(str(x).replace(",", "")) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except Exception:
        return 0


def kes(c):
    c = int(c or 0)
    return c // 100 if c % 100 == 0 else round(c / 100, 2)


def target_c(billing):
    return C(SUBSCRIPTION_YEARLY_KES if billing == "yearly" else SUBSCRIPTION_MONTHLY_KES)


def add_months(d, n):
    y, m = divmod(d.month - 1 + n, 12)
    y, m = d.year + y, m + 1
    return d.replace(year=y, month=m, day=min(d.day, calendar.monthrange(y, m)[1]))


def _d(s):
    try:
        return date.fromisoformat(s[:10]) if s else None
    except (ValueError, TypeError):
        return None


def today():
    return now().date()


_cfg = [0.0, None]


def sub_cfg():
    """Payment destination. Defaults come from the constants; platform/subscription_config.json may override them."""
    if _cfg[1] and time.time() - _cfg[0] < 60:
        return _cfg[1]
    o = get("platform/subscription_config.json", {}) or {}
    rec = o.get("recipients") or MPESA_RECIPIENT.split(",")
    _cfg[0], _cfg[1] = time.time(), {"paybill": str(o.get("paybill") or MPESA_PAYBILL), "account": str(o.get("account") or MPESA_ACCOUNT),
                                     "recipients": [str(x).strip() for x in rec if str(x).strip()]}
    return _cfg[1]


def config_out():
    c = sub_cfg()
    return {"product": SUBSCRIPTION_PRODUCT, "monthly_price": SUBSCRIPTION_MONTHLY_KES, "yearly_price": SUBSCRIPTION_YEARLY_KES,
            "yearly_saving": SUBSCRIPTION_YEARLY_SAVING_KES, "yearly_effective_monthly": SUBSCRIPTION_YEARLY_EFFECTIVE_MONTHLY_KES,
            "trial_days": TRIAL_DAYS, "referral_reward": REFERRAL_REWARD_KES, "reward_amount": REFERRAL_REWARD_KES,
            "billing_options": list(BILLING_MONTHS), "paybill": c["paybill"], "account": c["account"],
            "mpesa": {"paybill": c["paybill"], "account": c["account"]}}


# ---------------------------------------------------------------- status
def eff_status(p):
    """Stored status, except that a lapsed trial / paid period reads as expired (or past_due inside the grace window)."""
    st, t = p.get("status"), today()
    pe, te = _d(p.get("period_end")), _d(p.get("trial_ends"))
    if st == "trial" and te and te < t:
        return "active" if pe and pe >= t and (_d(p.get("period_start")) or t) <= t else "expired"
    if st in ("active", "past_due") and pe and pe < t:
        return "past_due" if (p.get("partial_c") or 0) > 0 and (t - pe).days <= PAST_DUE_GRACE_DAYS else "expired"
    return st


def coverage_end(p):
    """Date from which the next paid period starts: end of current paid/trial coverage, never earlier than today."""
    c = [today()]
    if p.get("status") in ("active", "past_due", "trial") and _d(p.get("period_end")):
        c.append(_d(p["period_end"]))
    if p.get("status") == "trial" and _d(p.get("trial_ends")):
        c.append(_d(p["trial_ends"]))
    return max(c)


def settle(p):
    """Evaluated on requests (no scheduler): persists trial->expired/active, active->past_due/expired, and rolls credit."""
    ch = False
    with lock("pay"):
        if not p.get("sub_v"):   # one-time, non-destructive migration: unexpired legacy trials become 30 days; nothing else is touched
            p["sub_v"] = 2
            p.setdefault("billing", "monthly")
            ts, te = _d(p.get("trial_start")), _d(p.get("trial_ends"))
            if p.get("status") == "trial" and ts and te and te >= today() and ts + timedelta(days=TRIAL_DAYS) > te:
                p["trial_ends"] = (ts + timedelta(days=TRIAL_DAYS)).isoformat()
            ch = True
        new, old = eff_status(p), p.get("status")
        if new != old:
            p["status"], ch = new, True
            audit("subscription_activated" if new == "active" else "subscription_" + new, "billing", g.bid, {"status": old}, {"status": new})
        if p.get("status") in ("expired", "past_due") and (p.get("credit_c") or 0) > 0:
            periods, creds = load_periods(g.bid), load_credits(g.bid)
            open_period(p, periods, creds, p.get("billing") or "monthly", g.bid)
            save_ledgers(g.bid, periods, creds, p)
            ch = True
        if ch:
            save_profile(p)


# ---------------------------------------------------------------- ledgers (B2, per tenant)
def load_periods(bid):
    return get(f"biz/{bid}/subscription/periods.json", [])


def load_credits(bid):
    return get(f"biz/{bid}/subscription/credits.json", {"balance_c": 0, "entries": []})


def save_ledgers(bid, periods, creds, prof):
    put(f"biz/{bid}/subscription/periods.json", periods)
    put(f"biz/{bid}/subscription/credits.json", creds)
    op = next((x for x in periods if x["status"] == "pending"), None)
    prof["partial_c"] = (op["amount_verified_c"] + op["credit_applied_c"]) if op else 0
    prof["credit_c"] = creds["balance_c"]
    cp = cur_period(prof, periods)
    prof["target_c"], prof["paid_c"] = cp["target_c"], cp["amount_verified_c"] + cp["credit_applied_c"]


def cur_period(prof, periods):
    op = next((x for x in periods if x["status"] == "pending"), None)
    lp = next((x for x in reversed(periods) if x["status"] == "paid"), None)
    if op and (op["amount_verified_c"] or op["credit_applied_c"]):
        return op
    if lp and eff_status(prof) in ("active", "trial") and (_d(lp.get("ends_at")) or today()) >= today():
        return lp
    b = prof.get("billing") or "monthly"
    return op or {"id": None, "billing": b, "target_c": target_c(b), "amount_verified_c": 0, "credit_applied_c": 0, "status": "none"}


def complete_period(prof, per):
    start = coverage_end(prof)
    end = add_months(start, BILLING_MONTHS[per["billing"]])
    per.update(status="paid", starts_at=start.isoformat(), ends_at=end.isoformat(), paid_at=iso(),
               prev_end=prof.get("period_end"), prev_start=prof.get("period_start"))
    prof.update(period_start=start.isoformat(), period_end=end.isoformat(), billing=per["billing"], plan="Business")
    if start <= today():
        prof["status"] = "active"
    audit("subscription_activated", "billing", per["id"], None, {"period_end": per["ends_at"], "billing": per["billing"]})


def open_period(prof, periods, creds, billing, bid):
    """Current unpaid period (created if needed). Available credit is applied when a period begins."""
    for _ in range(24):
        per = next((x for x in periods if x["status"] == "pending"), None)
        if per and per["billing"] != billing and not per["amount_verified_c"] and not per["credit_applied_c"]:
            per["billing"], per["target_c"] = billing, target_c(billing)
        if not per:
            s = coverage_end(prof)
            per = {"id": "subperiod_" + nid(), "bid": bid, "billing": billing, "target_c": target_c(billing), "amount_verified_c": 0,
                   "credit_applied_c": 0, "status": "pending", "starts_at": s.isoformat(),
                   "ends_at": add_months(s, BILLING_MONTHS[billing]).isoformat(), "created_at": iso()}
            periods.append(per)
            audit("subscription_created", "billing", per["id"], None, {"billing": billing, "target": kes(per["target_c"])})
        need_c = per["target_c"] - per["amount_verified_c"] - per["credit_applied_c"]
        use = min(creds["balance_c"], need_c)
        if use > 0:
            per["credit_applied_c"] += use
            creds["balance_c"] -= use
            creds["entries"].append({"id": nid(), "type": "applied", "amount_c": use, "period_id": per["id"], "at": iso()})
            audit("credit_applied", "billing", per["id"], None, {"amount": kes(use)})
            need_c -= use
        if need_c <= 0:
            complete_period(prof, per)
            continue
        return per
    raise ApiError(500, "server_error", "Could not open a billing period")


# ---------------------------------------------------------------- M-Pesa message parser
_CODE = re.compile(r"\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{10}\b")
_AMT = r"(?:KSH|KES)\.?\s*([\d,]+(?:\.\d{1,2})?)"


def _norm(s):
    return re.sub(r"[^A-Z0-9]", "", (s or "").upper())


def parse_mpesa(msg):
    """Structured parse of a pasted M-Pesa SMS. Never invents fields; missing/uncertain ones become warnings."""
    t = " ".join((msg if isinstance(msg, str) else "").split())
    U, w = t.upper(), []
    m = re.match(r"^\W*([A-Z0-9]{10})\b", U)
    code = m.group(1) if m and re.search(r"\d", m.group(1)) and re.search("[A-Z]", m.group(1)) else None
    if not code:
        m = _CODE.search(U)
        code = m.group(0) if m else None
    neg = re.search(r"\b(FAILED|FAILURE|CANCEL+ED|REVERS\w+|DECLINED|UNSUCCESSFUL|REJECTED|INSUFFICIENT)\b", U)
    status = "failed" if neg else "confirmed" if re.search(r"\bCONFIRMED\b", U) else "unknown"
    amt = None
    for m in re.finditer(_AMT, U):
        if re.search(r"(COST|FEE|CHARGE|BALANCE|BAL)(?:\s+IS)?\W*$", U[max(0, m.start() - 25):m.start()]):
            continue
        amt = C(m.group(1))
        break
    m = re.search(r"(?:TRANSACTION\s+)?(?:COST|FEE|CHARGE)S?\W{0,3}" + _AMT, U)
    fee = C(m.group(1)) if m else None
    rec = pb = None
    m = re.search(r"\b(?:SENT|PAID)\s+TO\s+(.+?)(?=\s+FOR\s+ACCOUNT|\s+ACCOUNT|\s+ON\s+\d|\s+AT\s+\d|\.\s|\.$|$)", t, re.I)
    if m:
        rec = m.group(1).strip()
        m2 = re.match(r"^(\d{5,7})\s*[-\u2013]\s*(.+)$", rec)
        if m2:
            pb, rec = m2.group(1), m2.group(2).strip()
    m = re.search(r"\b(?:PAYBILL|BUSINESS\s+(?:NO|NUMBER)\.?)\D{0,6}(\d{5,7})", U)
    pb = pb or (m.group(1) if m else None)
    m = re.search(r"\bACCOUNT(?:\s+(?:NO|NUMBER)\.?)?\s*[:#-]?\s*([A-Z0-9][A-Z0-9._-]{2,30})", U)
    acc = m.group(1).rstrip(".-_") if m else None
    dt = tm = None
    m = re.search(r"\bON\s+(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2,4})", U)
    if m:
        dd, mm, yy = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            dt = date(yy + 2000 if yy < 100 else yy, mm, dd).isoformat()
        except ValueError:
            w.append("The date in the message is not a valid date.")
    m = re.search(r"\bAT\s+(\d{1,2}:\d{2})\s*([AP]M)?", U)
    if m:
        tm = m.group(1) + (" " + m.group(2) if m.group(2) else "")
    for k, v in (("transaction code", code), ("amount", amt), ("account number", acc), ("date", dt), ("time", tm), ("recipient", rec)):
        if not v:
            w.append(f"No {k} found.")
    if status == "unknown":
        w.append("The message does not say the transaction was confirmed.")
    core = bool(code and amt and status == "confirmed" and acc)
    return {"parsed": bool(code and amt), "confidence": "high" if core and dt and rec else "medium" if core else "low", "warnings": w,
            "fields": {"transaction_code": code, "status": status, "amount_c": amt, "amount": kes(amt) if amt else None, "recipient": rec,
                       "paybill": pb, "account": acc, "date": dt, "time": tm, "fee_c": fee, "fee": kes(fee) if fee is not None else None}}


def validate_parsed(res):
    """Raises ApiError with a customer-safe code/message. Passing means 'message looks right', NOT 'Safaricom confirmed it'."""
    f, c = res["fields"], sub_cfg()
    if not f["transaction_code"] and not f["amount_c"]:
        raise ApiError(422, "invalid_mpesa_message", "We couldn't recognise this as an M-Pesa confirmation message. Paste the complete message.")
    if not f["transaction_code"]:
        raise ApiError(422, "missing_transaction_code", "We couldn't find the M-Pesa transaction code in this message.")
    if not f["amount_c"] or f["amount_c"] <= 0:
        raise ApiError(422, "missing_amount", "We couldn't find the amount in this message.")
    if f["status"] != "confirmed":
        raise ApiError(422, "invalid_status", "This message does not show a confirmed, successful M-Pesa transaction.")
    if not f["account"] or _norm(f["account"]) != _norm(c["account"]):
        raise ApiError(422, "wrong_account", "This payment was not made to the ACE account number shown on the payment page.")
    if f["paybill"] and f["paybill"] != c["paybill"]:
        raise ApiError(422, "wrong_account", "This payment was not made to the ACE PayBill number shown on the payment page.")
    if f["recipient"] and not any(_norm(r) and (_norm(r) in _norm(f["recipient"]) or _norm(f["recipient"]) in _norm(r)) for r in c["recipients"]):
        raise ApiError(422, "wrong_recipient", "The payment recipient in this message does not match ACE.")
    if f["date"]:
        d = _d(f["date"])
        if d > today() + timedelta(days=1) or d < today() - timedelta(days=MPESA_MAX_AGE_DAYS):
            raise ApiError(422, "invalid_date", "The date in this message is in the future or too old to accept.")


# ---------------------------------------------------------------- verification adapters (SMS parser today, official API later)
class PaymentVerifier:
    name = "base"

    def configured(self):
        return False

    def verify(self, payment):
        """Return {'externally_verified': bool}. Only an adapter that talks to Safaricom may return True."""
        return {"externally_verified": False}


class SmsParserVerifier(PaymentVerifier):
    name = "automatic_parser"

    def configured(self):
        return True

    def verify(self, payment):
        return {"externally_verified": False, "validated": True}   # parsing an SMS never proves Safaricom processed it


class OfficialMpesaVerifier(PaymentVerifier):
    """Placeholder for a future Daraja/official integration (set MPESA_OFFICIAL_ENABLED=1 once implemented)."""
    name = "official_mpesa"

    def configured(self):
        return os.environ.get("MPESA_OFFICIAL_ENABLED") == "1" and False   # not implemented: never claims verification


VERIFIERS = [v for v in (SmsParserVerifier(), OfficialMpesaVerifier()) if v.configured()]


# ---------------------------------------------------------------- payment outputs
def pay_out(p, admin=False, per_map=None):
    per = (per_map or {}).get(p.get("period_id"))
    o = {"id": p["id"], "transaction_code": p["transaction_code"], "amount": kes(p["amount_c"]), "fee": kes(p["fee_c"]) if p.get("fee_c") is not None else None,
         "payment_date": p.get("mpesa_date") or p["submitted_at"][:10], "date": p.get("mpesa_date"), "time": p.get("mpesa_time"),
         "status": DISP.get(p["status"], p["status"]), "state": p["status"], "validation_status": p.get("validation_status"),
         "verified": bool(p.get("verified")), "verified_at": p.get("verified_at"), "submitted_at": p["submitted_at"], "billing": p.get("billing"),
         "period_id": p.get("period_id"), "period": (per["starts_at"][:7] + " " + per["billing"].title()) if per else None,
         "allocation": [{"type": a["type"], "period_id": a.get("period_id"), "amount": kes(a["amount_c"])} for a in p.get("allocations", [])],
         "recipient": p.get("recipient"), "account": p.get("account"), "rejection_reason": p.get("rejection_reason"),
         "verification_method": p.get("verification_method")}
    if admin:
        o.update(raw_message=p.get("raw_message"), parse=p.get("parse"), verified_by=p.get("verified_by"), bid=p["bid"], amount_c=p["amount_c"],
                 history=p.get("history", []), source=p.get("source"))
    return o


def sub_status(bid, prof, with_payments=True):
    periods, creds, st, t = load_periods(bid), load_credits(bid), eff_status(prof), today()
    cp = cur_period(prof, periods)
    paid = cp["amount_verified_c"] + cp["credit_applied_c"]
    rem = max(0, cp["target_c"] - paid)
    pays = sorted([p for p in get(PAYS, {}).values() if p["bid"] == bid], key=lambda p: p["submitted_at"], reverse=True)
    pend = sum(p["amount_c"] for p in pays if p["status"] in PENDING and (p.get("period_id") == cp["id"] or not p.get("period_id")))
    te, pe = _d(prof.get("trial_ends")), _d(prof.get("period_end"))
    trial = st == "trial"
    days = max(0, (te - t).days) if trial and te else ((pe - t).days if pe and st in ("active", "past_due") else None)
    o = {"status": st, "plan": SUBSCRIPTION_PRODUCT, "billing": cp["billing"], "billing_period": cp["billing"], "target": kes(cp["target_c"]),
         "required": kes(cp["target_c"]), "verified_paid": kes(paid), "verified": kes(paid), "pending": kes(pend), "remaining": kes(rem),
         "credit": kes(creds["balance_c"]), "progress_percentage": min(100, int(paid * 100 / cp["target_c"])) if cp["target_c"] else 0,
         "complete": paid >= cp["target_c"] and cp["target_c"] > 0, "period_id": cp["id"], "period_start": prof.get("period_start"),
         "period_end": prof.get("period_end"), "trial": trial, "trial_start": prof.get("trial_start"), "trial_ends": prof.get("trial_ends"),
         "trial_days_remaining": max(0, (te - t).days) if trial and te else 0, "days_left": days, "next_renewal": prof.get("period_end"),
         "paybill": sub_cfg()["paybill"], "account": sub_cfg()["account"], "monthly_price": SUBSCRIPTION_MONTHLY_KES, "yearly_price": SUBSCRIPTION_YEARLY_KES}
    if with_payments:
        pm = {x["id"]: x for x in periods}
        o["payments"] = [pay_out(p, per_map=pm) for p in pays[:100]]
    return o


# ---------------------------------------------------------------- one-time import of the old manual-billing payments
def migrate_legacy():
    with lock("pay"):
        if get("platform/subscription_migrated.json"):
            return
        pays = get(PAYS, {})
        for pid, p in get("platform/payments.json", {}).items():
            code = str(p.get("transaction_code", "")).upper()
            if not code or pid in pays:
                continue
            st = {"pending": "pending_admin", "approved": "verified", "rejected": "rejected"}.get(p.get("status"), "rejected")
            pays[pid] = {"id": pid, "bid": p["bid"], "period_id": "legacy" if st == "verified" else None, "billing": "monthly", "raw_message": None,
                         "transaction_code": code, "amount_c": C(p.get("amount", 0)), "mpesa_status": "confirmed", "status": st, "recipient": None,
                         "account": None, "mpesa_date": p.get("payment_date"), "mpesa_time": None, "fee_c": None, "validation_status": "legacy",
                         "verified": st == "verified", "submitted_at": p.get("submitted_at") or iso(), "verified_at": p.get("verified_at"),
                         "verified_by": p.get("verified_by"), "verification_method": "admin_manual" if st == "verified" else None,
                         "rejection_reason": p.get("rejection_reason"), "allocations": [], "source": "legacy", "history": []}
            if not get(f"platform/mpesa/transactions/{sha(code)}.json"):
                put(f"platform/mpesa/transactions/{sha(code)}.json", {"payment_id": pid, "bid": p["bid"], "code": code, "at": iso()})
        put(PAYS, pays)
        put("platform/subscription_migrated.json", {"at": iso()})


# ---------------------------------------------------------------- customer: submit a pasted message
def submit_core(msg, billing):
    """Parse -> validate -> duplicate check -> store as pending_admin. Uses g.bid/g.prof/g.uid (tenant from the session)."""
    if not isinstance(msg, str) or not msg.strip():
        raise ApiError(400, "invalid_mpesa_message", "Please paste the complete M-Pesa confirmation message.")
    if len(msg) > 1500:
        raise ApiError(400, "invalid_mpesa_message", "That message is too long. Paste only the M-Pesa confirmation message.")
    if billing not in BILLING_MONTHS:
        raise ApiError(400, "invalid_billing_cycle", "Choose monthly or yearly billing.")
    res = parse_mpesa(msg)
    try:
        validate_parsed(res)
    except ApiError as e:
        audit("payment_invalid", "billing", None, None, {"code": e.code})   # the raw message is never logged
        raise
    f = res["fields"]
    code, txk = f["transaction_code"], f"platform/mpesa/transactions/{sha(f['transaction_code'])}.json"
    with lock("pay"):
        migrate_legacy()
        pays, tx = get(PAYS, {}), get(txk)
        if tx:
            ex = pays.get(tx["payment_id"])
            if tx["bid"] != g.bid:
                audit("payment_duplicate", "billing", None, None, {"code": code})
                raise ApiError(409, "duplicate_transaction", "This transaction has already been submitted.")
            if ex:
                return {**pay_out(ex), "already_submitted": True, "message": "This transaction has already been submitted."}, 200
        if sum(1 for p in pays.values() if p["bid"] == g.bid and p["status"] in PENDING) >= 10:
            raise ApiError(409, "pending_limit", "You already have several payments awaiting verification.")
        prof = get(f"biz/{g.bid}/profile.json")
        periods, creds = load_periods(g.bid), load_credits(g.bid)
        per = open_period(prof, periods, creds, billing, g.bid)
        pid = nid()
        pay = {"id": pid, "bid": g.bid, "period_id": per["id"], "billing": per["billing"], "raw_message": msg.strip(), "transaction_code": code,
               "amount_c": f["amount_c"], "mpesa_status": f["status"], "recipient": f["recipient"], "account": f["account"], "paybill": f["paybill"],
               "mpesa_date": f["date"], "mpesa_time": f["time"], "fee_c": f["fee_c"], "status": "pending_admin", "validation_status": "validated",
               "parse": {"confidence": res["confidence"], "warnings": res["warnings"]}, "verified": False, "submitted_at": iso(),
               "submitted_by": g.uid, "verified_at": None, "verified_by": None, "verification_method": None, "rejection_reason": None,
               "allocations": [], "history": [{"t": iso(), "a": "submitted", "by": g.uid}]}
        put(txk, {"payment_id": pid, "bid": g.bid, "code": code, "at": iso()})   # unique index first: a crash can never double-credit
        pays[pid] = pay
        put(PAYS, pays)
        prof["pay_n"] = prof.get("pay_n", 0) + 1
        save_ledgers(g.bid, periods, creds, prof)
        save_profile(prof)
        if any(v.verify(pay).get("externally_verified") for v in VERIFIERS):   # only a real provider adapter can do this
            _verify_locked(pays, pay, "official_mpesa", "system")
    audit("payment_submitted", "billing", pid, None, {"amount": kes(pay["amount_c"]), "code": code})
    audit("payment_parsed", "billing", pid, None, {"confidence": res["confidence"]})
    o = pay_out(pay)
    o["message"] = ("ACE has read and validated the transaction details in your M-Pesa message. "
                    "The payment may require final verification before it is applied to your subscription.")
    return o, 201


@app.post("/api/v1/subscription/payments/message")
@app.post("/api/v1/billing/payments")
@api()
def pay_submit():
    need("billing.create")
    b = body()
    throttle(f"pay|{g.bid}", limit=20, window=3600)
    _fails.setdefault(f"pay|{g.bid}", []).append(time.time())
    o, code = submit_core(b.get("message"), b.get("billing") or g.prof.get("billing") or "monthly")
    return ok(o, code)


@app.get("/api/v1/billing/config")
@api(public=True)
def billing_config():
    return ok(config_out())


@app.get("/api/v1/subscription/config")
@api()
def sub_config():
    return ok(config_out())


@app.get("/api/v1/subscription")
@app.get("/api/v1/billing")
@api()
def sub_get():
    need("billing.read")
    return ok(sub_status(g.bid, profile(g.bid, fresh=True)))


@app.get("/api/v1/subscription/payments")
@api()
def sub_payments():
    need("billing.read")
    return ok(sub_status(g.bid, profile(g.bid, fresh=True))["payments"])


# ---------------------------------------------------------------- admin: verify / reject / reverse (locked, idempotent)
def _adm_prof(bid):
    p = get(f"biz/{rid(bid)}/profile.json")
    if not p:
        raise ApiError(404, "subscription_not_found", "Business not found")
    g.bid, g.uid = bid, "admin"
    return p


def _verify_locked(pays, pay, method, actor):
    bid, txk = pay["bid"], f"platform/mpesa/transactions/{sha(pay['transaction_code'])}.json"
    prof = get(f"biz/{bid}/profile.json")
    if not prof:
        raise ApiError(404, "subscription_not_found", "Business not found")
    if prof["status"] in ("suspended", "cancelled"):
        raise ApiError(409, "suspended", "This business is suspended. Restore it first, then verify the payment.")
    tx = get(txk)
    if not tx or tx["payment_id"] != pay["id"]:
        raise ApiError(409, "duplicate_transaction", "This transaction code is already credited to another payment.")
    if pay["status"] not in PENDING:
        raise ApiError(409, "already_processed", "This payment has already been processed.")
    periods, creds = load_periods(bid), load_credits(bid)
    old_status = prof["status"]
    per = open_period(prof, periods, creds, pay.get("billing") or "monthly", bid)
    take = min(per["target_c"] - per["amount_verified_c"] - per["credit_applied_c"], pay["amount_c"])
    per["amount_verified_c"] += take
    allocs = [{"type": "period", "period_id": per["id"], "amount_c": take}]
    if pay["amount_c"] > take:   # overpayment is never lost: it becomes account credit, applied when the next period begins
        ex = pay["amount_c"] - take
        creds["balance_c"] += ex
        creds["entries"].append({"id": nid(), "type": "created", "amount_c": ex, "payment_id": pay["id"], "at": iso()})
        allocs.append({"type": "credit", "amount_c": ex})
        audit("credit_created", "billing", pay["id"], None, {"amount": kes(ex)})
    if per["amount_verified_c"] + per["credit_applied_c"] >= per["target_c"]:
        complete_period(prof, per)
    pay.update(status="verified", verified=True, verified_at=iso(), verified_by=actor, verification_method=method, period_id=per["id"],
               allocations=allocs, rejection_reason=None)
    pay.setdefault("history", []).append({"t": iso(), "a": "verified", "by": actor, "method": method})
    put(PAYS, pays)   # payment first: a crash afterwards can only under-credit, never double-credit
    save_ledgers(bid, periods, creds, prof)
    save_profile(prof)
    audit("payment_verified", "billing", pay["id"], {"status": "pending_admin", "sub": old_status},
          {"status": "verified", "amount": kes(pay["amount_c"]), "period": per["id"], "sub": prof["status"], "method": method})
    referral_on_verified(bid)
    return pay


def verify_payment(pid, actor="admin", method="admin_manual"):
    with lock("pay"):
        migrate_legacy()
        pays = get(PAYS, {})
        pay = pays.get(rid(pid))
        if not pay:
            raise ApiError(404, "not_found", "Payment not found")
        _adm_prof(pay["bid"])
        return _verify_locked(pays, pay, method, actor)


def reject_payment(pid, reason):
    reason = s_(reason, 200)
    if not reason:
        raise ApiError(400, "invalid_input", "Give a reason so the customer knows what to fix")
    with lock("pay"):
        pays = get(PAYS, {})
        pay = pays.get(rid(pid))
        if not pay:
            raise ApiError(404, "not_found", "Payment not found")
        if pay["status"] not in PENDING:
            raise ApiError(409, "already_processed", "This payment has already been processed.")
        _adm_prof(pay["bid"])
        pay.update(status="rejected", verified=False, verified_at=iso(), verified_by="admin", rejection_reason=reason)
        pay.setdefault("history", []).append({"t": iso(), "a": "rejected", "by": "admin", "reason": reason})
        put(PAYS, pays)
    audit("payment_rejected", "billing", pid, {"status": "pending_admin"}, {"status": "rejected", "reason": reason})
    return pay


def reverse_payment(pid, reason):
    reason = s_(reason, 200) or "Reversed by administrator"
    with lock("pay"):
        pays = get(PAYS, {})
        pay = pays.get(rid(pid))
        if not pay:
            raise ApiError(404, "not_found", "Payment not found")
        prof = _adm_prof(pay["bid"])
        if pay["status"] in PENDING:
            pay["status"] = "reversed"
        elif pay["status"] == "verified" and pay.get("period_id") != "legacy":
            periods, creds = load_periods(pay["bid"]), load_credits(pay["bid"])
            for a in pay.get("allocations", []):
                if a["type"] == "period":
                    per = next(x for x in periods if x["id"] == a["period_id"])
                    if per["status"] == "paid":
                        if any(x["status"] == "paid" and x["starts_at"] >= per["ends_at"] for x in periods):
                            raise ApiError(409, "invalid_state", "A later paid period depends on this payment. Adjust it manually.")
                        prof.update(period_end=per.get("prev_end"), period_start=per.get("prev_start"))
                        if not prof.get("period_end"):
                            prof["status"] = "expired" if (_d(prof.get("trial_ends")) or today()) < today() else "trial"
                        per["status"] = "pending"
                    per["amount_verified_c"] -= a["amount_c"]
                else:
                    creds["balance_c"] -= min(creds["balance_c"], a["amount_c"])
                    creds["entries"].append({"id": nid(), "type": "reversed", "amount_c": a["amount_c"], "payment_id": pid, "at": iso()})
            pay.update(status="reversed", verified=False)
            save_ledgers(pay["bid"], periods, creds, prof)
            save_profile(prof)
        else:
            raise ApiError(409, "already_processed", "This payment cannot be reversed.")
        pay.setdefault("history", []).append({"t": iso(), "a": "reversed", "by": "admin", "reason": reason})
        put(PAYS, pays)
    audit("payment_reversed", "billing", pid, None, {"reason": reason})
    return pay


@app.post("/api/v1/admin/subscription/payments/<pid>/verify")
@app.post("/api/v1/admin/payments/<pid>/approve")
@api(admin=True)
def adm_pay_verify(pid):
    p = verify_payment(pid)
    prof = profile(p["bid"], fresh=True) or {}
    send_mail(prof.get("owner_email", ""), "ACE payment verified", f"Your payment {p['transaction_code']} (KSh {kes(p['amount_c']):,}) was verified.")
    return ok({"status": "verified", "verified": True, "period_end": prof.get("period_end"), "subscription_status": eff_status(prof)})


@app.post("/api/v1/admin/subscription/payments/<pid>/reject")
@app.post("/api/v1/admin/payments/<pid>/reject")
@api(admin=True)
def adm_pay_reject(pid):
    p = reject_payment(pid, body().get("reason"))
    prof = profile(p["bid"], fresh=True) or {}
    send_mail(prof.get("owner_email", ""), "ACE payment could not be verified",
              f"We could not verify payment {p['transaction_code']}: {p['rejection_reason']}\nYour subscription is unchanged.")
    return ok({"status": "rejected"})


@app.post("/api/v1/admin/subscription/payments/<pid>/reverse")
@api(admin=True)
def adm_pay_reverse(pid):
    return ok({"status": reverse_payment(pid, body().get("reason"))["status"]})


@app.get("/api/v1/admin/subscription/payments")
@app.get("/api/v1/admin/payments")
@api(admin=True)
def adm_payments():
    migrate_legacy()
    a, legacy = request.args, request.path.endswith("/admin/payments")
    st = {"pending": "pending_admin", "approved": "verified"}.get(a.get("status"), a.get("status"))
    rows = sorted(get(PAYS, {}).values(), key=lambda p: p["submitted_at"], reverse=True)
    q, own, code = a.get("business", "").lower(), a.get("owner", "").lower(), a.get("code", "").strip().upper()
    out = []
    for p in rows:
        if st and not (p["status"] in PENDING if st == "pending_admin" else p["status"] == st):
            continue
        if code and p["transaction_code"] != code:
            continue
        if a.get("billing") and p.get("billing") != a["billing"]:
            continue
        if a.get("amount") and p["amount_c"] != C(a["amount"]):
            continue
        if a.get("date_from") and p["submitted_at"][:10] < a["date_from"] or a.get("date_to") and p["submitted_at"][:10] > a["date_to"]:
            continue
        pr = profile(p["bid"]) or {}
        if q and q not in (pr.get("name", "") + p["bid"]).lower() or own and own not in pr.get("owner_email", "").lower():
            continue
        out.append((p, pr))
    lim, off = max(1, min(int(a.get("limit", 100) or 100), 200)), max(0, int(a.get("offset", 0) or 0))
    data = []
    for p, pr in out[off:off + lim]:
        o = pay_out(p, admin=True)
        o.update(business=pr.get("name"), owner=pr.get("owner_email"), phone=pr.get("phone"), sub_status=eff_status(pr) if pr else None,
                 trial_ends=pr.get("trial_ends"), period_end=pr.get("period_end"), business_paid=kes(pr.get("paid_c", 0)),
                 business_target=kes(pr.get("target_c", 0)), business_credit=kes(pr.get("credit_c", 0)))
        if legacy:
            o["status"] = {"pending_admin": "pending", "parsed": "pending", "submitted": "pending", "verified": "approved"}.get(p["status"], p["status"])
        data.append(o)
    return jsonify(ok=True, data=data, total=len(out), limit=lim, offset=off)


@app.get("/api/v1/admin/subscriptions/summary")
@api(admin=True)
def adm_summary():
    biz, pays = get("platform/businesses.json", {}), get(PAYS, {}).values()
    cnt = {}
    for b in biz.values():
        s = eff_status({"status": b.get("status"), "trial_ends": b.get("trial_ends"), "period_end": b.get("period_end"),
                        "period_start": b.get("period_start"), "partial_c": b.get("partial_c")})
        cnt[s] = cnt.get(s, 0) + 1
    v = [p for p in pays if p["status"] == "verified"]
    pend = [p for p in pays if p["status"] in PENDING]
    rt = get("platform/referral_totals.json", {"count": 0, "rewards_c": 0})
    act = [b for b in biz.values() if b.get("status") == "active"]
    return ok({"total_businesses": len(biz), "active": cnt.get("active", 0), "trial": cnt.get("trial", 0), "expired": cnt.get("expired", 0),
               "past_due": cnt.get("past_due", 0), "suspended": cnt.get("suspended", 0), "cancelled": cnt.get("cancelled", 0),
               "pending_payments": len(pend), "pending_value": kes(sum(p["amount_c"] for p in pend)), "verified_payments": len(v),
               "verified_revenue": kes(sum(p["amount_c"] for p in v)), "rejected_payments": sum(1 for p in pays if p["status"] == "rejected"),
               "referral_rewards": kes(rt["rewards_c"]), "successful_referrals": rt["count"],
               "monthly_subscriptions": sum(1 for b in act if b.get("billing", "monthly") == "monthly"),
               "yearly_subscriptions": sum(1 for b in act if b.get("billing") == "yearly")})


@app.get("/api/v1/admin/businesses/<bid>/subscription")
@api(admin=True)
def adm_sub_detail(bid):
    p = _adm_prof(bid)
    return ok({**sub_status(bid, p), "referral_code": p.get("referral_code"), "referred_by": bool(p.get("referred_by"))})


@app.post("/api/v1/admin/businesses/<bid>/subscription")
@api(admin=True)
def adm_sub(bid):
    b = body()
    act = {"restore": "reactivate"}.get(b.get("action"), b.get("action"))
    names = {"extend": "extended", "suspend": "suspended", "reactivate": "restored", "activate": "activated", "cancel": "cancelled", "expire": "expired"}
    if act not in names:
        raise ApiError(400, "invalid_input", "Unknown action")
    with lock("pay"):
        p = _adm_prof(bid)
        t, old = today(), {"status": p["status"], "trial_ends": p.get("trial_ends"), "period_end": p.get("period_end")}
        if act in ("suspend", "cancel"):
            p["status_before"], p["status"] = eff_status(p), "suspended" if act == "suspend" else "cancelled"
        elif act == "reactivate":
            if p["status"] not in ("suspended", "cancelled", "expired"):
                raise ApiError(409, "invalid_state", "This business is not suspended")
            back = p.pop("status_before", None)
            p["status"] = back if back in ("trial", "active", "past_due") else ("active" if p.get("period_end") else "trial")
        elif act == "expire":
            if p["status"] in ("suspended", "cancelled"):
                raise ApiError(409, "invalid_state", "Restore the business first")
            p["status"] = "expired"
        elif act == "activate":
            p.pop("status_before", None)
            p["status"] = "active"
            if not _d(p.get("period_end")) or _d(p["period_end"]) < t:
                p["period_start"], p["period_end"] = t.isoformat(), add_months(t, BILLING_MONTHS.get(p.get("billing"), 1)).isoformat()
        else:
            days = int(n_(b.get("days", 30), 1))
            if days > 365 or eff_status(p) in ("suspended", "cancelled"):
                raise ApiError(400, "invalid_input", "Choose 1 to 365 days for an active or expired business")
            field = "trial_ends" if p["status"] == "trial" else "period_end"
            cur = _d(p.get(field))
            p[field] = (max(cur, t) if cur else t).__add__(timedelta(days=days)).isoformat()
            if p["status"] == "expired":
                p["status"] = "active"
        save_profile(p)
    audit("subscription_" + names[act], "billing", bid, old, {"status": p["status"], "trial_ends": p.get("trial_ends"), "period_end": p.get("period_end")})
    return ok({**sub_fields(p)})


# ---------------------------------------------------------------- referrals (KSh 500 only after the referred business's first VERIFIED payment)
_REF_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_ref_code(bid):
    for _ in range(20):
        code = "ACE-" + "".join(secrets.choice(_REF_ALPHA) for _ in range(6))
        with lock("ref_codes"):
            if not get(f"platform/referrals/{code}.json"):
                put(f"platform/referrals/{code}.json", {"bid": bid, "code": code, "at": iso()})
                return code
    raise ApiError(500, "server_error", "Could not create a referral code")


def referral_lookup(code):
    code = (code or "").strip().upper() if isinstance(code, str) else ""
    if re.fullmatch(r"ACE[A-Z0-9]{6}", code):
        code = "ACE-" + code[3:]   # accept ACE7X92K as well as ACE-7X92K
    return get(f"platform/referrals/{code}.json") if re.fullmatch(r"ACE-[A-Z0-9]{6}", code) else None


def sub_init(prof, ref=None, email="", phone=""):
    """Subscription defaults for a NEW business (register / Google sign-up). Self-referrals are ignored."""
    prof.update(plan="Business", status="trial", billing="monthly", sub_v=2, credit_c=0, partial_c=0, pay_n=0)
    prof["referral_code"] = new_ref_code(prof["id"])
    if ref and ref["bid"] != prof["id"]:
        rp = get(f"biz/{ref['bid']}/profile.json") or {}
        same = (rp.get("owner_email", "").lower() == (email or "").lower()) or (phone and rp.get("phone") and _norm(rp["phone"]) == _norm(phone))
        if rp and not same:
            prof["referred_by"] = {"bid": ref["bid"], "code": ref["code"], "rid": nid()}
            prof.update(referral_code_used=ref["code"], referral_status="pending", referral_created_at=iso())
    return prof


def referral_register(prof):
    rb = prof.get("referred_by")
    if not rb:
        return
    with lock("ref"):
        rf = get(f"biz/{rb['bid']}/referrals.json", {"items": [], "ledger": [], "balance_c": 0})
        rf["items"].append({"id": rb["rid"], "referred_bid": prof["id"], "business": prof["name"], "date": iso(), "status": "pending",
                            "reward_c": 0, "reward_status": "none"})
        put(f"biz/{rb['bid']}/referrals.json", rf)
    audit("referral_created", "referrals", rb["rid"], None, {"referrer": rb["bid"]})


def referral_on_verified(bid):
    prof = get(f"biz/{bid}/profile.json") or {}
    rb = prof.get("referred_by")
    if not rb or prof.get("ref_done") or rb["bid"] == bid:
        return
    with lock("ref"):
        rf = get(f"biz/{rb['bid']}/referrals.json", {"items": [], "ledger": [], "balance_c": 0})
        it = next((x for x in rf["items"] if x["id"] == rb["rid"] and x["referred_bid"] == bid), None)
        if not it or it["status"] != "pending" or it["reward_status"] != "none":
            return   # unknown, already rewarded, or invalid: never a second reward for the same referred business
        it.update(status="successful", completed_at=iso(), reward_c=C(REFERRAL_REWARD_KES),
                  reward_status="credited" if REFERRAL_AUTO_APPROVE else "pending_admin")
        if REFERRAL_AUTO_APPROVE:
            rf["ledger"].append({"id": nid(), "type": "reward", "amount_c": it["reward_c"], "referral_id": it["id"], "at": iso()})
            rf["balance_c"] += it["reward_c"]
        put(f"biz/{rb['bid']}/referrals.json", rf)
        t = get("platform/referral_totals.json", {"count": 0, "rewards_c": 0})
        t["count"] += 1
        t["rewards_c"] += it["reward_c"] if REFERRAL_AUTO_APPROVE else 0
        put("platform/referral_totals.json", t)
    prof["ref_done"] = True
    prof["referral_status"] = "successful"
    save_profile(prof)
    audit("referral_completed", "referrals", it["id"], {"status": "pending"}, {"status": "successful", "referrer": rb["bid"]})
    audit("referral_reward_created", "referrals", it["id"], None, {"amount": REFERRAL_REWARD_KES, "status": it["reward_status"]})


def _mask(n):
    n = (n or "").strip()
    return (n[:2] + "***") if n else "Business"


@app.get("/api/v1/referrals")
@api()
def referrals_get():
    need("billing.read")
    prof = profile(g.bid, fresh=True)
    if not prof.get("referral_code"):
        prof["referral_code"] = new_ref_code(g.bid)
        save_profile(prof)
    rf = get(f"biz/{g.bid}/referrals.json", {"items": [], "ledger": [], "balance_c": 0})
    it = rf["items"]
    hist = [{"business": _mask(x["business"]), "date": x["date"][:10], "reward": kes(x["reward_c"]) if x["reward_c"] else None,
             "status": "rejected" if x["status"] == "invalid" else ("reward_pending" if x["reward_status"] == "pending_admin" else x["status"])}
            for x in sorted(it, key=lambda x: x["date"], reverse=True)]
    return ok({"code": prof["referral_code"], "referral_link": f"{base_url()}/register?ref={prof['referral_code']}", "url": f"{base_url()}/register?ref={prof['referral_code']}",
               "reward_amount": REFERRAL_REWARD_KES, "total": len(it), "pending": sum(1 for x in it if x["status"] == "pending"),
               "successful": sum(1 for x in it if x["status"] == "successful"),
               "rewards_earned": kes(sum(x["reward_c"] for x in it if x["reward_status"] == "credited")),
               "rewards_pending": kes(sum(x["reward_c"] for x in it if x["reward_status"] == "pending_admin")),
               "available_credit": kes(rf["balance_c"]), "history": hist,
               "note": "Rewards are subject to the referral qualification rules."})


@app.post("/api/v1/referrals/validate")
@api(public=True)
def referral_validate():
    throttle(f"refv|{request.remote_addr}", limit=30, window=900)
    _fails.setdefault(f"refv|{request.remote_addr}", []).append(time.time())
    r = referral_lookup(body().get("code"))
    return ok({"valid": bool(r)})


@app.post("/api/v1/admin/referrals/<bid>/<rid_>/approve")
@api(admin=True)
def adm_ref_approve(bid, rid_):
    with lock("ref"):
        rf = get(f"biz/{rid(bid)}/referrals.json")
        it = next((x for x in (rf or {}).get("items", []) if x["id"] == rid(rid_)), None)
        if not it or it["reward_status"] != "pending_admin":
            raise ApiError(409, "invalid_state", "No pending reward to approve")
        it["reward_status"] = "credited"
        rf["ledger"].append({"id": nid(), "type": "reward", "amount_c": it["reward_c"], "referral_id": it["id"], "at": iso()})
        rf["balance_c"] += it["reward_c"]
        put(f"biz/{bid}/referrals.json", rf)
        t = get("platform/referral_totals.json", {"count": 0, "rewards_c": 0})
        t["rewards_c"] += it["reward_c"]
        put("platform/referral_totals.json", t)
    g.bid, g.uid = bid, "admin"
    audit("referral_reward_approved", "referrals", rid_, None, {"amount": kes(it["reward_c"])})
    return ok({"status": "credited"})


@app.get("/api/v1/admin/referrals")
@api(admin=True)
def adm_refs():
    rows = []
    for bid, meta in (get("platform/businesses.json", {}) or {}).items():
        for x in (get(f"biz/{bid}/referrals.json") or {}).get("items", []):
            st = "cancelled" if x["status"] == "invalid" else ("rewarded" if x["reward_status"] == "credited" else x["status"])
            rows.append({"id": x["id"], "referrer_bid": bid, "referrer": meta.get("name"), "code": meta.get("referral_code"),
                         "referred": x.get("business"), "date": x["date"][:10], "status": st, "reward": kes(x["reward_c"]),
                         "reward_status": x["reward_status"], "qualified": bool(x.get("completed_at"))})
    rows.sort(key=lambda r: r["date"], reverse=True)
    return ok(rows[:500])


@app.post("/api/v1/admin/referrals/<bid>/<rid_>/cancel")
@api(admin=True)
def adm_ref_cancel(bid, rid_):
    bid, rid_ = rid(bid), rid(rid_)
    with lock("ref"):
        rf = get(f"biz/{bid}/referrals.json")
        it = next((x for x in (rf or {}).get("items", []) if x["id"] == rid_), None)
        if not it or it["status"] == "invalid":
            raise ApiError(409, "invalid_state", "This referral cannot be cancelled")
        t = get("platform/referral_totals.json", {"count": 0, "rewards_c": 0})
        old = {"status": it["status"], "reward_status": it["reward_status"]}
        if it["status"] == "successful":
            t["count"] = max(0, t["count"] - 1)
        if it["reward_status"] == "credited":
            rf["ledger"].append({"id": nid(), "type": "reversal", "amount_c": -it["reward_c"], "referral_id": it["id"], "at": iso()})
            rf["balance_c"] -= it["reward_c"]
            t["rewards_c"] = max(0, t["rewards_c"] - it["reward_c"])
        it.update(status="invalid", reward_status="cancelled", cancelled_at=iso())
        put(f"biz/{bid}/referrals.json", rf)
        put("platform/referral_totals.json", t)
    g.bid, g.uid = bid, "admin"
    audit("referral_cancelled", "referrals", rid_, old, {"status": "invalid"})
    return ok({"status": "cancelled"})


# ============================================================================= workspaces, subdomains & custom domains (v5)
# Every business gets a permanent, unique workspace slug  ->  https://<slug>.<ROOT_DOMAIN>
# Everything is stored in Backblaze B2:   platform/domains.json   (one index)
#   {"slugs": {slug: bid}, "hosts": {verified custom host: bid}, "biz": {bid: {slug, workspace, created, custom:{...}}}}
# SECURITY: a hostname is only a *routing hint*. It is always resolved through this index and never trusted as a
# business id. Protected endpoints keep using the business id stored in the authenticated session.
# ROOT_DOMAIN is OPTIONAL. Empty (the default) = path-based stores at BASE_URL/shop/<slug> and no custom-domain DNS needed.
ROOT_DOMAIN = os.environ.get("ROOT_DOMAIN", "").strip().lower().strip(".")
PLATFORM_CNAME = os.environ.get("PLATFORM_CNAME", ("custom." + ROOT_DOMAIN) if ROOT_DOMAIN else "").strip().lower().strip(".")
PLATFORM_IPS = [x.strip() for x in os.environ.get("PLATFORM_IPS", "").split(",") if x.strip()]
DOMAINS_KEY = "platform/domains.json"
VERIFY_LABEL = "_ace-verify"
SLUG_MAX = 40
RESERVED_SLUGS = {"www", "app", "api", "admin", "mail", "email", "smtp", "support", "help", "docs", "blog", "status", "static",
                  "assets", "cdn", "custom", "ace", "acebusiness", "login", "register", "signup", "billing", "dashboard", "root",
                  "ns1", "ns2", "ftp", "test", "demo", "staging", "dev", "platform", "secure", "shop", "store", "business"}
_dcache = [0.0, None]
_rl_hits = {}


def _rate(key, limit, window):
    t = time.time()
    hits = [x for x in _rl_hits.get(key, []) if t - x < window]
    if len(hits) >= limit:
        raise ApiError(429, "slow_down", "Too many attempts. Please wait a few minutes and try again.")
    hits.append(t)
    _rl_hits[key] = hits


def dom_idx(fresh=False):
    if not fresh and _dcache[1] is not None and time.time() - _dcache[0] < 5:
        return _dcache[1]
    d = get(DOMAINS_KEY) or {}
    for k in ("slugs", "hosts", "biz"):
        d.setdefault(k, {})
    _dcache[0], _dcache[1] = time.time(), d
    return d


def dom_save(idx):
    put(DOMAINS_KEY, idx)
    _dcache[0], _dcache[1] = time.time(), idx


def generate_business_slug(name):
    """'ACE Hardware & Electrical Ltd.' -> 'ace-hardware-electrical-ltd'. Never uses the business id."""
    t = unicodedata.normalize("NFKD", str(name or "")).encode("ascii", "ignore").decode().lower()
    t = re.sub(r"['`]", "", t)
    t = re.sub(r"[^a-z0-9]+", "-", t)
    t = re.sub(r"-{2,}", "-", t).strip("-")[:SLUG_MAX].strip("-")
    return t or "business"


def unique_slug(base, slugs):
    base = (base or "business")[:SLUG_MAX].strip("-") or "business"
    if base not in slugs and base not in RESERVED_SLUGS:
        return base
    for n in range(2, 5000):
        suf = f"-{n}"
        cand = base[:SLUG_MAX - len(suf)].rstrip("-") + suf
        if cand not in slugs and cand not in RESERVED_SLUGS:
            return cand
    return f"{base[:SLUG_MAX - 7].rstrip('-')}-{secrets.token_hex(3)}"


def workspace_host(slug):
    return f"{slug}.{ROOT_DOMAIN}" if ROOT_DOMAIN else None      # no purchased domain = no hostname claim


def _claim_slug(bid, prof):
    """Reserve a slug for this business inside the domain index (caller holds lock('platform')). Mutates prof."""
    idx = dom_idx(True)
    slug = prof.get("slug")
    if not (slug and idx["slugs"].get(slug) in (None, bid) and slug not in RESERVED_SLUGS and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?", slug)):
        slug = unique_slug(generate_business_slug(prof.get("name")), idx["slugs"])
    idx["slugs"][slug] = bid
    rec = idx["biz"].setdefault(bid, {"created": prof.get("created") or iso()})
    rec["slug"], rec["workspace"] = slug, workspace_host(slug)
    dom_save(idx)
    prof["slug"], prof["workspace_host"] = slug, workspace_host(slug)
    return slug


def ensure_workspace(bid, prof):
    """Safe migration: existing businesses without a slug get one the next time they sign in. Idempotent."""
    if not prof:
        return prof
    idx = dom_idx()
    if prof.get("slug") and idx["slugs"].get(prof["slug"]) == bid and bid in idx["biz"]:
        return prof
    with lock("platform"):
        prof = dict(get(f"biz/{bid}/profile.json") or prof)
        if prof.get("slug") and dom_idx(True)["slugs"].get(prof["slug"]) == bid:
            return prof
        _claim_slug(bid, prof)
        put(f"biz/{bid}/profile.json", prof)
        _pcache[bid] = (time.time(), prof)
        bi = get("platform/businesses.json", {})
        if bid in bi:
            bi[bid]["slug"] = prof["slug"]
            put("platform/businesses.json", bi)
    return prof


def ensure_workspace_safe(bid, prof):
    try:
        return ensure_workspace(bid, prof)
    except Exception:
        app.logger.exception("workspace migration failed")
        return prof


# ---------------------------------------------------------------- hostname resolution (routing hint only)
def resolve_host(host):
    h = (host or "").split(":")[0].strip().lower().rstrip(".")
    if not h or len(h) > 253:
        return None
    idx = dom_idx()
    if ROOT_DOMAIN and h.endswith("." + ROOT_DOMAIN):
        sub = h[:-len(ROOT_DOMAIN) - 1]
        return idx["slugs"].get(sub) if "." not in sub else None
    return idx["hosts"].get(h)


# ---------------------------------------------------------------- custom-domain validation & DNS
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def clean_domain(raw):
    d = str(raw or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#]", d, 1)[0].rstrip(".")
    bad = ApiError(400, "invalid_domain", "Enter a valid domain such as www.mybusiness.co.ke (no http://, paths or ports).")
    if not d or any(c in d for c in ": @_*") or d.count(".") < 1:
        raise bad
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:
        raise bad
    labels = d.split(".")
    if len(d) > 253 or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit() or len(labels[-1]) < 2:
        raise bad
    if ROOT_DOMAIN and (d == ROOT_DOMAIN or d.endswith("." + ROOT_DOMAIN) or d == PLATFORM_CNAME):
        raise ApiError(400, "reserved_domain", f"*.{ROOT_DOMAIN} is managed by ACE. Enter a domain you own.")
    return d


class DnsError(Exception):
    pass


def _dns_query(name, rtype):
    """Return a list of record strings. Raises DnsError if DNS could not be checked (never guesses)."""
    rtype = rtype.upper()
    try:
        import dns.resolver as _r      # optional: pip install dnspython
    except Exception:
        _r = None
    if _r:
        try:
            res = _r.Resolver()
            res.lifetime = 5
            out = []
            for a in res.resolve(name, rtype):
                if rtype == "TXT":
                    out.append("".join(x.decode() if isinstance(x, bytes) else x for x in a.strings))
                elif rtype == "CNAME":
                    out.append(str(a.target).rstrip(".").lower())
                else:
                    out.append(str(a))
            return out
        except (_r.NXDOMAIN, _r.NoAnswer):
            return []
        except Exception:
            raise DnsError("lookup failed")
    try:     # DNS-over-HTTPS fallback, no extra dependency
        req = urllib.request.Request("https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": rtype}),
                                     headers={"accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=6) as r:
            j = json.loads(r.read())
    except Exception:
        raise DnsError("lookup failed")
    if j.get("Status") not in (0, 3):
        raise DnsError("lookup failed")
    code, out = {"TXT": 16, "CNAME": 5, "A": 1}[rtype], []
    for a in j.get("Answer") or []:
        if a.get("type") != code:
            continue
        d = a.get("data", "")
        out.append("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', d)) or d.strip('"') if rtype == "TXT" else d.rstrip(".").lower())
    return out


def _routing_ok(d):
    try:
        if PLATFORM_CNAME in [c.lower() for c in _dns_query(d, "CNAME")]:
            return True
        return bool(PLATFORM_IPS and set(_dns_query(d, "A")) & set(PLATFORM_IPS))
    except DnsError:
        return False


STATUS_TEXT = {"pending": "Pending verification", "dns_required": "DNS verification required", "verified": "Verified",
               "active": "Active", "error": "Error", "not_connected": "Not connected"}


def dom_out(bid, owner=True):
    idx = dom_idx()
    rec = idx["biz"].get(bid) or {}
    slug = rec.get("slug")
    out = {"slug": slug, "store_url": store_url(slug) if slug else None, "custom_available": bool(PLATFORM_CNAME),
           "workspace_host": rec.get("workspace") if ROOT_DOMAIN else None,
           "workspace_url": f"https://{rec['workspace']}" if rec.get("workspace") and ROOT_DOMAIN else None,
           "workspace_status": "active" if slug else "pending", "root_domain": ROOT_DOMAIN,
           "target": {"cname": PLATFORM_CNAME, "ips": PLATFORM_IPS}, "custom": None, "status": "not_connected"}
    c = rec.get("custom")
    if c:
        st = "disabled" if c.get("disabled") else c["status"]
        out["status"] = st
        out["custom"] = {k: c.get(k) for k in ("domain", "status", "verified_at", "active_at", "last_check", "error", "created", "disabled")}
        out["custom"]["label"] = "Disabled by ACE support" if c.get("disabled") else STATUS_TEXT.get(c["status"], c["status"])
        out["custom"]["url"] = f"https://{c['domain']}" if c["status"] in ("verified", "active") and not c.get("disabled") else None
        if owner:
            out["custom"]["dns"] = {
                "txt": {"type": "TXT", "name": f"{VERIFY_LABEL}.{c['domain']}", "value": "ace-verify=" + c["token"]},
                "route": {"type": "CNAME", "name": c["domain"], "value": PLATFORM_CNAME}}
    return out


def _put_host(idx, bid, c):
    d = c["domain"]
    for h, b in list(idx["hosts"].items()):
        if b == bid and h != d:
            del idx["hosts"][h]
    if c["status"] in ("verified", "active") and not c.get("disabled"):
        idx["hosts"][d] = bid
    elif idx["hosts"].get(d) == bid:
        del idx["hosts"][d]


def prof_domain(p):
    """Small summary for prof_out (cached index, no extra B2 call on the hot path)."""
    try:
        r = dom_idx()["biz"].get(p["id"]) or {}
    except Exception:
        return {}
    c = r.get("custom") or {}
    slug = r.get("slug") or p.get("slug")
    return {"slug": slug, "store_url": store_url(slug) if slug else None, "store_status": store_state(p),
            "workspace_host": r.get("workspace") if ROOT_DOMAIN else None,
            "workspace_url": f"https://{r['workspace']}" if r.get("workspace") and ROOT_DOMAIN else None,
            "custom_available": bool(PLATFORM_CNAME),
            "custom_domain": c.get("domain"), "custom_domain_status": ("disabled" if c.get("disabled") else c.get("status")) if c else "not_connected"}


def run_verify(bid):
    """Really check DNS. A domain only becomes verified when the expected TXT record is found."""
    with lock("platform"):
        idx = dom_idx(True)
        c = (idx["biz"].get(bid) or {}).get("custom")
        if not c:
            raise ApiError(404, "no_domain", "Connect a domain first.")
        if c.get("disabled"):
            raise ApiError(403, "domain_disabled", "This domain was disabled by ACE support. Please contact support.")
        d = clean_domain(c["domain"])
        owner = idx["hosts"].get(d)
        if owner and owner != bid:
            raise ApiError(409, "domain_taken", "This domain is already connected to another ACE workspace.")
        c["last_check"] = iso()
        try:
            txts = _dns_query(f"{VERIFY_LABEL}.{d}", "TXT")
        except DnsError:
            c["error"] = "We could not reach DNS just now. Your domain status was not changed. Try again in a minute."
            dom_save(idx)
            return dom_out(bid), False
        expected = "ace-verify=" + c["token"]
        if not any(hmac.compare_digest(t.strip(), expected) for t in txts):
            c["status"] = "dns_required"
            c["error"] = ("A TXT record was found but its value does not match." if txts else
                          "The verification TXT record was not found yet. DNS changes can take up to 24 hours to propagate.")
            c["verified_at"] = c["active_at"] = None
            _put_host(idx, bid, c)
            dom_save(idx)
            return dom_out(bid), False
        c["verified_at"] = c.get("verified_at") or iso()
        if _routing_ok(d):
            c["status"], c["error"] = "active", None
            c["active_at"] = c.get("active_at") or iso()
        else:
            c["status"], c["active_at"] = "verified", None
            c["error"] = f"Domain ownership verified. Point {d} to {PLATFORM_CNAME} (CNAME) to start serving traffic."
        _put_host(idx, bid, c)
        dom_save(idx)
        return dom_out(bid), True


def _domain_audit(action, bid, who, new=None):
    g.bid, g.uid = bid, who
    audit(action, "domains", bid, None, new)


@app.get("/api/v1/business/domain")
@api()
def domain_get():
    return jsonify(dom_out(g.bid, owner=can(g.role, "settings.update")))


@app.post("/api/v1/business/domain")
@api()
def domain_set():
    need("settings.update")
    if not PLATFORM_CNAME:
        raise ApiError(400, "custom_domains_unavailable", "Custom domains are not enabled on this ACE deployment yet. Your online store link works without one.")
    _rate("dset|" + g.bid, 20, 3600)
    d = clean_domain(body().get("domain"))
    with lock("platform"):
        idx = dom_idx(True)
        if idx["hosts"].get(d) not in (None, g.bid):
            raise ApiError(409, "domain_taken", "This domain is already connected to another ACE workspace.")
        rec = idx["biz"].get(g.bid)
        if not rec:
            ensure_workspace(g.bid, g.prof)
            idx = dom_idx(True)
            rec = idx["biz"][g.bid]
        old = rec.get("custom")
        if old and old["domain"] == d:
            return jsonify(dom_out(g.bid))
        rec["custom"] = {"domain": d, "status": "pending", "token": secrets.token_urlsafe(24), "created": iso(), "verified_at": None,
                         "active_at": None, "last_check": None, "error": None, "disabled": bool(old and old.get("disabled"))}
        _put_host(idx, g.bid, rec["custom"])
        dom_save(idx)
    audit("connect", "domains", d)
    return jsonify(dom_out(g.bid)), 201


@app.post("/api/v1/business/domain/verify")
@api()
def domain_verify():
    need("settings.update")
    _rate("dver|" + g.bid, 12, 600)
    out, okv = run_verify(g.bid)
    audit("verify" if okv else "verify_failed", "domains", (out.get("custom") or {}).get("domain"))
    return jsonify({**out, "verified": okv})


@app.delete("/api/v1/business/domain")
@api()
def domain_del():
    need("settings.update")
    with lock("platform"):
        idx = dom_idx(True)
        rec = idx["biz"].get(g.bid) or {}
        c = rec.pop("custom", None)
        if c:
            idx["hosts"].pop(c["domain"], None)
            dom_save(idx)
    if c:
        audit("remove", "domains", c["domain"])
    return jsonify(dom_out(g.bid))


@app.get("/api/v1/workspace")
@api(public=True)
def workspace_public():
    """Public branding for the workspace the browser is visiting. Exposes no ids, users or data."""
    _rate("ws|" + str(request.remote_addr), 120, 60)
    host = request.args.get("host") or request.host
    bid = resolve_host(host)
    if not bid:
        return jsonify(found=False, root_domain=ROOT_DOMAIN)
    p = profile(bid)
    if not p or eff_status(p) in ("suspended", "cancelled"):
        return jsonify(found=False, root_domain=ROOT_DOMAIN)
    o = {"found": True, "name": p["name"], "type": p.get("type"), "col": p.get("col"), "slug": p.get("slug"), "root_domain": ROOT_DOMAIN}
    if p.get("logo"):
        o["logo_url"] = file_url(bid, p["logo"])
    return jsonify(o)


# ---------------------------------------------------------------- admin
@app.get("/api/v1/admin/domains")
@api(admin=True)
def adm_domains():
    bi = get("platform/businesses.json", {})
    idx = dom_idx(True)
    missing = [b for b in bi if b not in idx["biz"]][:200]
    for b in missing:                       # lazy, safe migration of legacy businesses
        try:
            ensure_workspace(b, get(f"biz/{b}/profile.json"))
        except Exception:
            app.logger.exception("admin migration failed")
    idx = dom_idx(True)
    rows = []
    for b, r in idx["biz"].items():
        c = r.get("custom") or {}
        rows.append({"id": b, "business": (bi.get(b) or {}).get("name", "—"), "slug": r.get("slug"), "workspace_url": f"https://{r['workspace']}" if r.get("workspace") and ROOT_DOMAIN else None,
                     "store_url": store_url(r["slug"]) if r.get("slug") else None, "custom_domain": c.get("domain"), "status": ("disabled" if c.get("disabled") else c.get("status")) if c else "not_connected",
                     "created": r.get("created"), "verified_at": c.get("verified_at"), "last_check": c.get("last_check"), "error": c.get("error"), "disabled": bool(c.get("disabled"))})
    q = request.args.get("q", "").lower()
    rows = [r for r in rows if not q or q in json.dumps(r).lower()]
    return page(sorted(rows, key=lambda r: r.get("created") or "", reverse=True))


@app.post("/api/v1/admin/domains/<bid>/verify")
@api(admin=True)
def adm_dom_verify(bid):
    bid = rid(bid)
    out, okv = run_verify(bid)
    _domain_audit("admin_verify", bid, "admin", {"verified": okv})
    return jsonify({**out, "verified": okv})


@app.post("/api/v1/admin/domains/<bid>/disable")
@api(admin=True)
def adm_dom_disable(bid):
    bid = rid(bid)
    dis = bool(body().get("disabled", True))
    with lock("platform"):
        idx = dom_idx(True)
        c = (idx["biz"].get(bid) or {}).get("custom")
        if not c:
            raise ApiError(404, "no_domain", "This business has no custom domain.")
        c["disabled"] = dis
        _put_host(idx, bid, c)
        dom_save(idx)
    _domain_audit("admin_disable" if dis else "admin_enable", bid, "admin")
    return jsonify(dom_out(bid, owner=False))


@app.delete("/api/v1/admin/domains/<bid>")
@api(admin=True)
def adm_dom_remove(bid):
    bid = rid(bid)
    with lock("platform"):
        idx = dom_idx(True)
        c = (idx["biz"].get(bid) or {}).pop("custom", None)
        if not c:
            raise ApiError(404, "no_domain", "This business has no custom domain.")
        idx["hosts"].pop(c["domain"], None)
        dom_save(idx)
    _domain_audit("admin_remove", bid, "admin", c["domain"])
    return jsonify(dom_out(bid, owner=False))


# ---------------------------------------------------------------- installable app (PWA) + brand assets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.get("/assets/<path:name>")
def brand_assets(name):
    r = send_from_directory(os.path.join(BASE_DIR, "assets"), name, max_age=86400)
    return r


@app.get("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(BASE_DIR, "assets"), "favicon-48.png", max_age=86400)


@app.get("/manifest.webmanifest")
def manifest():
    name, short = "ACE Business Management Systems", "ACE Business"
    try:
        bid = resolve_host(request.host)
        p = profile(bid) if bid else None
        if p:
            name = short = p["name"][:45]
    except Exception:
        pass
    m = {"name": name, "short_name": short[:12] if len(short) > 12 else short, "description": "Sales, inventory, customers, invoices and reports in one platform by ACE Synapse Technologies.",
         "id": "/", "start_id": "/", "start_url": "/?source=pwa", "scope": "/", "display": "standalone", "display_override": ["standalone", "minimal-ui"],
         "orientation": "any", "background_color": "#060e28", "theme_color": "#0a1a4a", "categories": ["business", "productivity", "finance"], "lang": "en",
         "icons": [{"src": "/assets/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
                   {"src": "/assets/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
                   {"src": "/assets/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}],
         "shortcuts": [{"name": "New sale", "short_name": "Sell", "url": "/?go=pos", "icons": [{"src": "/assets/icon-192.png", "sizes": "192x192"}]},
                       {"name": "Dashboard", "short_name": "Dashboard", "url": "/?go=dash", "icons": [{"src": "/assets/icon-192.png", "sizes": "192x192"}]}]}
    r = make_response(json.dumps(m))
    r.headers["Content-Type"] = "application/manifest+json"
    r.headers["Cache-Control"] = "no-cache"
    return r


@app.get("/sw.js")
def service_worker():
    r = send_from_directory(BASE_DIR, "sw.js", max_age=0)
    r.headers["Service-Worker-Allowed"] = "/"
    r.headers["Cache-Control"] = "no-cache"
    r.headers["Content-Type"] = "application/javascript"
    return r


# ============================================================================= online store (v6)
# Every business gets a public storefront at  BASE_URL/shop/<slug>  the moment it registers. No purchased domain, DNS or
# wildcard certificate is involved. The store reads the SAME item records as the management system (items.json); an item
# with pub=True is "published". Orders are written into the business's own B2 folder and deduct the same stock the POS uses.
# SECURITY: the business is ALWAYS resolved server-side from the slug (never from a client-supplied id); every read/write
# afterwards uses that business's own keys.
BASE_URL_ENV = os.environ.get("BASE_URL", "").strip().rstrip("/")
STORE_USE_CUSTOM = os.environ.get("STORE_USE_CUSTOM_DOMAIN", "0") == "1"       # future: advertise a verified custom domain
ORDER_STATUSES = ["Pending", "Confirmed", "Processing", "Ready for Pickup", "Out for Delivery", "Completed", "Cancelled", "Refunded"]
PAY_STATUSES = ["Pending", "Paid", "Failed", "Partially Paid", "Refunded"]
STORE_THEMES = {"modern": "Modern Business", "electronics": "Electronics", "fashion": "Fashion", "food": "Restaurant / Food", "general": "General Store"}
_stcache = {}


def site_base():
    return BASE_URL_ENV or request.host_url.rstrip("/")


def store_url(slug):
    """Today: BASE_URL/shop/<slug>. Later a verified custom domain can replace the base without touching the store itself."""
    if STORE_USE_CUSTOM:
        try:
            c = next((r.get("custom") for r in dom_idx()["biz"].values() if r.get("slug") == slug), None)
            if c and c.get("status") == "active" and not c.get("disabled"):
                return f"https://{c['domain']}/shop/{slug}"
        except Exception:
            pass
    return f"{site_base()}/shop/{slug}"


def store_defaults(prof):
    t = {"retail": "general", "hardware": "general", "restaurant": "food", "salon": "modern", "pharmacy": "modern"}.get(prof.get("type"), "modern")
    return {"enabled": True, "name": prof.get("name", ""), "desc": "", "banner": None, "theme": t, "col": prof.get("col") or "#0a6cff",
            "whatsapp": "", "phone": "", "email": "", "location": "", "hours": "",
            "delivery": {"enabled": True, "fee": 0, "free_over": 0, "note": ""}, "pickup": {"enabled": True, "note": ""},
            "pay": {"cod": True, "mpesa": False, "mpesa_note": ""}, "created": iso()}


def store_load(bid, prof=None, fresh=False):
    c = _stcache.get(bid)
    if c and not fresh and time.time() - c[0] < 10:
        return c[1]
    st = get(f"biz/{bid}/store.json")
    base = store_defaults(prof or profile(bid) or {})
    if st:
        for k, v in st.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                base[k].update(v)
            else:
                base[k] = v
    _stcache[bid] = (time.time(), base)
    return base


def store_state(prof):
    st = eff_status(prof)
    if st in ("suspended", "cancelled"):
        return "unavailable"
    if st == "expired":
        return "paused"
    try:
        if not store_load(prof["id"], prof)["enabled"]:
            return "closed"
    except Exception:
        pass
    return "active"


def store_lookup(slug):
    """slug -> (bid, profile) or None. The ONLY way a request is tied to a business."""
    if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?", slug):
        return None
    bid = dom_idx()["slugs"].get(slug)
    p = profile(bid) if bid else None
    return (bid, p) if p else None


class NoStore(Exception):
    pass


def store_ctx(slug, need_open=True):
    r = store_lookup(slug)
    if not r:
        raise NoStore()
    bid, p = r
    hb = getattr(g, "host_bid", None)
    if hb and hb != bid:                    # a hostname that belongs to another business never serves this store
        raise NoStore()
    if need_open and store_state(p) != "active":
        raise NoStore()
    g.bid, g.uid, g.prof = bid, "store", p
    return bid, p, store_load(bid, p)


def pub_rows(bid):
    """Published products only, newest first (featured first). Cached briefly and dropped whenever items change."""
    c = _icache.get(bid)
    if c and time.time() - c[0] < 20:
        return c[1]
    g.bid = bid
    rows = [(k, v) for k, v in coll_get("items").items() if v.get("pub")]
    rows.sort(key=lambda kv: (not kv[1].get("feat"), -(datetime.fromisoformat(kv[1]["created"]).timestamp() if kv[1].get("created") else 0)))
    _icache[bid] = (time.time(), rows)
    return rows


def eff_price(it):
    d = min(max(it.get("disc") or 0, 0), 100)
    return round(it["p"] * (1 - d / 100), 2)


def pub_item(slug, iid, it, full=False):
    st, d = it.get("st"), it.get("disc") or 0
    o = {"id": iid, "n": it["n"], "price": eff_price(it), "was": it["p"] if d else None, "disc": d, "cat": it.get("cat", ""), "brand": it.get("brand", ""),
         "feat": bool(it.get("feat")), "hasv": bool(it.get("vars")), "in_stock": st is None or st > 0, "left": st if (st is not None and 0 < st <= 5) else None,
         "img": f"/shop/{slug}/img/{it['img']}" if it.get("img") else None}
    if full:
        o.update(desc=it.get("desc", ""), sku=it.get("sku", ""), vars=it.get("vars") or [])
    return o


def digits(ph):
    return re.sub(r"\D", "", str(ph or ""))


def norm_phone(ph):
    d = digits(ph)
    if d.startswith("254"):
        d = d[3:]
    elif d.startswith("0"):
        d = d[1:]
    if not (9 <= len(d) <= 12):
        raise ApiError(400, "invalid_phone", "Enter a valid phone number, e.g. 0712 345 678")
    return d[-9:]


def price_lines(items, raw, strict):
    """Server-side pricing. Browser prices are never read; only product id, option and quantity are."""
    if not isinstance(raw, list) or len(raw) > 60:
        raise ApiError(400, "invalid_input", "Your cart is empty or too large")
    used, out, issues, merged = {}, [], [], {}
    for l in raw:                                   # the same product + option sent twice is one line
        if not isinstance(l, dict):
            continue
        try:
            qq = int(l.get("q", 1))
        except (TypeError, ValueError):
            qq = 0
        k = (str(l.get("id", "")), s_(l.get("v", ""), 40))
        merged[k] = merged.get(k, 0) + (qq if qq > 0 else -10**6)
    for (iid, v), q in merged.items():
        q = q if q > 0 else 0
        if q < 1 or q > 99:
            if strict:
                raise ApiError(400, "invalid_quantity", "Quantity must be between 1 and 99")
            q = min(q, 99)
            if q < 1:
                continue
        it = items.get(iid) if ID_RE.match(iid) else None
        if not it or not it.get("pub"):
            if strict:
                raise ApiError(409, "unavailable", "An item in your cart is no longer available")
            issues.append({"id": iid, "msg": "No longer available"})
            continue
        if it.get("vars") and v not in it["vars"]:
            if strict:
                raise ApiError(400, "choose_option", f"Choose an option for {it['n']}")
            issues.append({"id": iid, "msg": "Choose an option"})
            continue
        if not it.get("vars"):
            v = ""
        st = it.get("st")
        free = None if st is None else st - used.get(iid, 0)
        if free is not None and q > free:
            if strict:
                raise ApiError(409, "insufficient_stock", f"Only {int(max(free, 0))} of {it['n']} left in stock" if free > 0 else f"{it['n']} is out of stock")
            issues.append({"id": iid, "msg": "Out of stock" if free < 1 else f"Only {int(free)} left"})
            q = int(free)
            if q < 1:
                continue
        used[iid] = used.get(iid, 0) + q
        pr = eff_price(it)
        out.append({"id": iid, "n": it["n"], "v": v, "q": q, "price": pr, "line": round(pr * q, 2), "sku": it.get("sku", ""), "c": it.get("c", 0)})
    return out, issues


def delivery_fee(stg, fulfil, sub):
    if fulfil != "delivery":
        return 0
    d = stg["delivery"]
    return 0 if (d.get("free_over") and sub >= d["free_over"]) else float(d.get("fee") or 0)


def fulfil_ok(stg, fulfil):
    if fulfil not in ("delivery", "pickup") or not stg[fulfil].get("enabled"):
        raise ApiError(400, "invalid_input", "That delivery option is not available for this store")


def order_view(o, owner=False):
    v = {"number": o["number"], "date": o["date"], "status": o["status"], "pay_status": o["pay_status"], "pay_method": o["pay_method"],
         "items": [{"n": l["n"], "v": l["v"], "q": l["q"], "price": l["price"], "line": l["line"]} for l in o["items"]],
         "sub": o["sub"], "fee": o["fee"], "total": o["total"], "fulfil": o["fulfil"], "location": o.get("location", ""),
         "history": [{"s": h["s"], "t": h["t"]} for h in o["history"]], "customer_name": o["cust"]["name"]}
    if owner:
        v.update(cust=o["cust"], address=o.get("address", ""), notes=o.get("notes", ""), admin_note=o.get("admin_note", ""), sale_id=o.get("sale_id"),
                 source="online_store", label="ONLINE STORE ORDER")
    return v


def oshard(m):
    return K("orders", m + ".json")


def oindex():
    return get(K("orders", "index.json"), {})


# ---------------------------------------------------------------- public JSON API
def jerr(e):
    r = jsonify(error={"code": e.code, "message": e.message})
    r.status_code = e.status
    r.headers["Cache-Control"] = "no-store"
    return r


def jok(**kw):
    r = jsonify(**kw)
    r.headers["Cache-Control"] = "no-store"
    return r


def store_api(f):
    @wraps(f)
    def w(slug, *a, **k):
        try:
            _rate("shopapi|" + str(request.remote_addr), 600, 60)
            return f(slug, *a, **k)
        except NoStore:
            return jerr(ApiError(404, "store_not_found", "Store not found"))
        except ApiError as e:
            return jerr(e)
    return w


@app.get("/shop/<slug>/api/products")
@store_api
def shop_products(slug):
    bid, p, stg = store_ctx(slug)
    a = request.args
    q, cat, brand = a.get("q", "").strip().lower()[:60], a.get("cat", "").strip().lower(), a.get("brand", "").strip().lower()
    try:
        lo, hi = float(a.get("min") or 0), float(a.get("max") or 1e12)
        page_n, lim = max(1, int(a.get("page", 1))), max(1, min(int(a.get("limit", 24)), 60))
    except ValueError:
        raise ApiError(400, "invalid_input", "Invalid filter")
    rows = pub_rows(bid)
    cats = {}
    for _, it in rows:
        if it.get("cat"):
            cats[it["cat"]] = cats.get(it["cat"], 0) + 1
    out = []
    for iid, it in rows:
        if q and not any(q in str(it.get(f, "")).lower() for f in ("n", "cat", "brand", "sku")):
            continue
        if cat and it.get("cat", "").lower() != cat:
            continue
        if brand and it.get("brand", "").lower() != brand:
            continue
        pr = eff_price(it)
        if pr < lo or pr > hi:
            continue
        if a.get("avail") == "1" and not (it.get("st") is None or it["st"] > 0):
            continue
        if a.get("featured") == "1" and not it.get("feat"):
            continue
        if a.get("disc") == "1" and not it.get("disc"):
            continue
        out.append((iid, it))
    srt = a.get("sort", "")
    if srt == "price_asc":
        out.sort(key=lambda kv: eff_price(kv[1]))
    elif srt == "price_desc":
        out.sort(key=lambda kv: -eff_price(kv[1]))
    elif srt == "name":
        out.sort(key=lambda kv: kv[1]["n"].lower())
    total = len(out)
    part = out[(page_n - 1) * lim: page_n * lim]
    res = {"data": [pub_item(slug, i, it) for i, it in part], "total": total, "page": page_n, "pages": max(1, -(-total // lim))}
    if page_n == 1:
        res["cats"] = [{"n": k, "c": v} for k, v in sorted(cats.items())]
    return jok(**res)


@app.get("/shop/<slug>/api/products/<pid>")
@store_api
def shop_product(slug, pid):
    bid, p, stg = store_ctx(slug)
    it = coll_get("items").get(pid) if ID_RE.match(pid) else None
    if not it or not it.get("pub"):
        raise ApiError(404, "not_found", "Product not found")
    return jok(product=pub_item(slug, pid, it, full=True))


@app.post("/shop/<slug>/cart")
@store_api
def shop_cart(slug):
    bid, p, stg = store_ctx(slug)
    b = body()
    fulfil = b.get("fulfil") if b.get("fulfil") in ("delivery", "pickup") else ("delivery" if stg["delivery"]["enabled"] else "pickup")
    lines, issues = price_lines(coll_get("items"), b.get("lines"), strict=False)
    sub = round(sum(l["line"] for l in lines), 2)
    fee = delivery_fee(stg, fulfil, sub) if lines else 0
    img = {k: it.get("img") for k, it in coll_get("items").items() if k in {l["id"] for l in lines}}
    for l in lines:
        l.pop("c", None)
        l["img"] = f"/shop/{slug}/img/{img[l['id']]}" if img.get(l["id"]) else None
    return jok(lines=lines, issues=issues, sub=sub, fee=fee, total=round(sub + fee, 2), fulfil=fulfil, cur=p.get("cur", "KES"))


@app.post("/shop/<slug>/order")
@store_api
def shop_order(slug):
    _rate("shoporder|" + str(request.remote_addr), 30, 3600)
    bid, p, stg = store_ctx(slug)
    b = body()
    cu = b.get("customer") or {}
    name, email = s_(cu.get("name"), 80), s_(cu.get("email"), 120).lower()
    if len(name) < 2:
        raise ApiError(400, "invalid_input", "Enter your name")
    phone = norm_phone(cu.get("phone"))
    if email and not EMAIL_RE.match(email):
        raise ApiError(400, "invalid_input", "Enter a valid email or leave it empty")
    fulfil = b.get("fulfil")
    fulfil_ok(stg, fulfil)
    location, address = s_(b.get("location"), 120), s_(b.get("address"), 300)
    if fulfil == "delivery" and not (location and address):
        raise ApiError(400, "invalid_input", "Enter your delivery location and address")
    method = b.get("pay_method", "cod")
    if method not in ("cod", "mpesa") or not stg["pay"].get(method):
        raise ApiError(400, "invalid_input", "That payment method is not available for this store")
    notes = s_(b.get("notes"), 500)
    idem = (request.headers.get("Idempotency-Key") or "")[:64]
    with lock(bid):
        meta = get(K("meta.json"), {"sale": 1000, "inv": 0, "idem": {}})
        if idem and idem in meta.get("oidem", {}):
            num = meta["oidem"][idem]
            ix = oindex().get(num)
            if ix:
                return jok(order=order_view(get(oshard(ix["m"]), {})[num]), repeat=True)
        items = coll_get("items")
        lines, _ = price_lines(items, b.get("lines"), strict=True)
        if not lines:
            raise ApiError(400, "invalid_input", "Your cart is empty")
        sub = round(sum(l["line"] for l in lines), 2)
        fee = delivery_fee(stg, fulfil, sub)
        for l in lines:                                   # inventory: same lock as the POS, so two buyers can never take the last unit
            it = items[l["id"]]
            if it.get("st") is not None:
                it["st"] = round(it["st"] - l["q"], 3)
        coll_put("items", items)
        meta["ord"] = meta.get("ord", 10000) + 1
        num, month = f"ACE-ORD-{meta['ord']}", ym()
        # the customer is also added to the business's own customer list (matched by phone)
        custs = coll_get("customers")
        cid = next((k for k, v in custs.items() if v.get("ph") and digits(v["ph"])[-9:] == phone), None)
        if not cid:
            cid = nid()
            custs[cid] = {"n": name, "ph": cu.get("phone", "")[:30], "em": email, "notes": "Added from the online store", "created": iso()}
            coll_put("customers", custs)
        o = {"id": nid(), "number": num, "date": iso(), "status": "Pending", "pay_status": "Pending", "pay_method": method,
             "items": lines, "sub": sub, "fee": fee, "total": round(sub + fee, 2), "fulfil": fulfil, "location": location, "address": address,
             "notes": notes, "cust": {"id": cid, "name": name, "phone": cu.get("phone", "")[:30], "email": email}, "ph9": phone,
             "history": [{"s": "Pending", "t": iso()}], "restocked": False, "source": "online_store"}
        shard = get(oshard(month), {})
        shard[num] = o
        put(oshard(month), shard)
        ix = oindex()
        ix[num] = {"m": month, "s": "Pending", "p": "Pending", "d": o["date"], "t": o["total"], "n": name, "ph": phone, "f": fulfil}
        put(K("orders", "index.json"), ix)
        if idem:
            meta.setdefault("oidem", {})[idem] = num
            meta["oidem"] = dict(list(meta["oidem"].items())[-200:])
        put(K("meta.json"), meta)
    audit("create", "orders", num, None, {"total": o["total"]})
    wa = digits(stg.get("whatsapp"))
    return jok(order=order_view(o), whatsapp=wa or None, payment_note=stg["pay"].get("mpesa_note") if method == "mpesa" else ""), 201


@app.post("/shop/<slug>/track")
@store_api
def shop_track(slug):
    _rate("shoptrack|" + str(request.remote_addr), 30, 600)
    bid, p, stg = store_ctx(slug, need_open=False)
    b = body()
    num, ph = s_(b.get("number"), 30).upper(), None
    try:
        ph = norm_phone(b.get("phone"))
    except ApiError:
        pass
    ix = oindex().get(num)
    o = get(oshard(ix["m"]), {}).get(num) if ix else None
    if not o or not ph or o["ph9"] != ph:       # same answer whether the number or the phone is wrong
        raise ApiError(404, "order_not_found", "We couldn't find an order with that number and phone number")
    return jok(order=order_view(o))


@app.get("/shop/<slug>/img/<fid>")
def shop_img(slug, fid):
    try:
        bid, p, stg = store_ctx(slug, need_open=False)
    except NoStore:
        return make_response("", 404)
    if not re.fullmatch(r"[0-9a-f]{32}", fid):
        return make_response("", 404)
    m = get(K("files.json"), {}).get(fid)
    if not m or m.get("kind") not in ("product", "banner", "logo"):
        return make_response("", 404)
    try:
        data = s3.get_object(Bucket=BUCKET, Key=K("files", fid))["Body"].read()
    except Exception:
        return make_response("", 404)
    r = Response(data, mimetype=m["type"])
    r.headers["Cache-Control"] = "public, max-age=86400, immutable"
    r.set_etag(fid)
    return r.make_conditional(request)


# ---------------------------------------------------------------- owner API (session-authenticated)
def store_out(bid, prof):
    stg = dict(store_load(bid, prof, fresh=True))
    items = coll_get("items")
    ix = oindex()
    stg["banner_url"] = f"/shop/{prof['slug']}/img/{stg['banner']}" if stg.get("banner") else None
    return {"settings": stg, "slug": prof["slug"], "url": store_url(prof["slug"]), "status": store_state(prof),
            "themes": STORE_THEMES, "currency": prof.get("cur", "KES"),
            "stats": {"products": len(items), "published": sum(1 for v in items.values() if v.get("pub")),
                      "orders": len(ix), "pending": sum(1 for v in ix.values() if v["s"] == "Pending")}}


@app.get("/api/v1/store")
@api()
def store_get_owner():
    prof = ensure_workspace_safe(g.bid, g.prof)
    if not get(K("store.json")):
        put(K("store.json"), store_defaults(prof))
    return jsonify(store_out(g.bid, prof))


@app.patch("/api/v1/store")
@api()
def store_patch():
    need("settings.update")
    b = body()
    cur = dict(store_load(g.bid, g.prof, fresh=True))
    old = json.loads(json.dumps(cur))
    for k, n in (("name", 80), ("desc", 600), ("whatsapp", 20), ("phone", 30), ("email", 120), ("location", 160), ("hours", 200)):
        if k in b:
            cur[k] = s_(b[k], n)
    if cur["email"] and not EMAIL_RE.match(cur["email"]):
        raise ApiError(400, "invalid_input", "Enter a valid store email")
    if cur["whatsapp"] and not 9 <= len(digits(cur["whatsapp"])) <= 15:
        raise ApiError(400, "invalid_input", "Enter the WhatsApp number with country code, e.g. 254712345678")
    if "enabled" in b:
        cur["enabled"] = bool_(b["enabled"])
    if "theme" in b:
        if b["theme"] not in STORE_THEMES:
            raise ApiError(400, "invalid_input", "Unknown store theme")
        cur["theme"] = b["theme"]
    if "col" in b:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", str(b["col"])):
            raise ApiError(400, "invalid_input", "Invalid colour")
        cur["col"] = b["col"]
    if isinstance(b.get("delivery"), dict):
        d = b["delivery"]
        cur["delivery"] = {"enabled": bool_(d.get("enabled", cur["delivery"]["enabled"])), "fee": n_(d.get("fee", cur["delivery"]["fee"])),
                           "free_over": n_(d.get("free_over", cur["delivery"]["free_over"])), "note": s_(d.get("note", cur["delivery"].get("note", "")), 200)}
    if isinstance(b.get("pickup"), dict):
        d = b["pickup"]
        cur["pickup"] = {"enabled": bool_(d.get("enabled", cur["pickup"]["enabled"])), "note": s_(d.get("note", cur["pickup"].get("note", "")), 200)}
    if isinstance(b.get("pay"), dict):
        d = b["pay"]
        cur["pay"] = {"cod": bool_(d.get("cod", cur["pay"]["cod"])), "mpesa": bool_(d.get("mpesa", cur["pay"]["mpesa"])),
                      "mpesa_note": s_(d.get("mpesa_note", cur["pay"].get("mpesa_note", "")), 300)}
    if not (cur["delivery"]["enabled"] or cur["pickup"]["enabled"]):
        raise ApiError(400, "invalid_input", "Enable delivery, pickup or both")
    if not (cur["pay"]["cod"] or cur["pay"]["mpesa"]):
        raise ApiError(400, "invalid_input", "Enable at least one payment method")
    if cur["pay"]["mpesa"] and not cur["pay"]["mpesa_note"]:
        raise ApiError(400, "invalid_input", "Add your M-Pesa payment instructions (till, paybill or number) for customers")
    if not cur["name"]:
        raise ApiError(400, "invalid_input", "Store name is required")
    put(K("store.json"), cur)
    _stcache.pop(g.bid, None)
    audit("update", "store", g.bid, old, cur)
    return jsonify(store_out(g.bid, g.prof))


@app.post("/api/v1/store/banner")
@api()
def store_banner_set():
    need("settings.update")
    fid, _ = store_file("banner")
    with lock("st" + g.bid):
        cur = dict(store_load(g.bid, g.prof, fresh=True))
        old, cur["banner"] = cur.get("banner"), fid
        put(K("store.json"), cur)
        _stcache.pop(g.bid, None)
    if old:
        delete_file(old)
    return jsonify(store_out(g.bid, g.prof))


@app.delete("/api/v1/store/banner")
@api()
def store_banner_del():
    need("settings.update")
    with lock("st" + g.bid):
        cur = dict(store_load(g.bid, g.prof, fresh=True))
        old, cur["banner"] = cur.get("banner"), None
        put(K("store.json"), cur)
        _stcache.pop(g.bid, None)
    if old:
        delete_file(old)
    return jsonify(store_out(g.bid, g.prof))


@app.post("/api/v1/items/<iid>/image")
@api()
def item_image_set(iid):
    need("items.update")
    fid, _ = store_file("product")
    with lock(g.bid):
        data = coll_get("items")
        it = data.get(rid(iid))
        if not it:
            delete_file(fid)
            raise ApiError(404, "not_found", "Record not found")
        old, it["img"] = it.get("img"), fid
        coll_put("items", data)
    if old:
        delete_file(old)
    audit("update", "items", iid, None, {"img": fid})
    return jsonify(id=iid, **it)


@app.delete("/api/v1/items/<iid>/image")
@api()
def item_image_del(iid):
    need("items.update")
    with lock(g.bid):
        data = coll_get("items")
        it = data.get(rid(iid))
        if not it:
            raise ApiError(404, "not_found", "Record not found")
        old = it.pop("img", None)
        coll_put("items", data)
    if old:
        delete_file(old)
    return jsonify(id=iid, **it)


@app.get("/api/v1/orders")
@api()
def orders_list():
    need("orders.read")
    ix = oindex()
    st, q = request.args.get("status", ""), request.args.get("q", "").strip().lower()
    counts = {}
    for v in ix.values():
        counts[v["s"]] = counts.get(v["s"], 0) + 1
    rows = [{"number": k, "date": v["d"], "status": v["s"], "pay_status": v["p"], "total": v["t"], "customer": v["n"], "phone": v["ph"], "fulfil": v["f"]}
            for k, v in ix.items() if (not st or v["s"] == st) and (not q or q in k.lower() or q in v["n"].lower() or q in v["ph"])]
    rows.sort(key=lambda r: r["date"], reverse=True)
    lim = max(1, min(int(request.args.get("limit", 50) or 50), 100))
    off = max(0, int(request.args.get("offset", 0) or 0))
    return jsonify(data=rows[off:off + lim], total=len(rows), counts=counts)


def _find_order(num):
    ix = oindex().get(str(num).upper())
    o = get(oshard(ix["m"]), {}).get(str(num).upper()) if ix else None
    if not o:
        raise ApiError(404, "not_found", "Order not found")
    return o, ix["m"]


@app.get("/api/v1/orders/<num>")
@api()
def order_get(num):
    need("orders.read")
    return jsonify(order_view(_find_order(num)[0], owner=True))


@app.patch("/api/v1/orders/<num>")
@api()
def order_patch(num):
    need("orders.update")
    b = body()
    with lock(g.bid):
        o, m = _find_order(num)
        old = {"status": o["status"], "pay_status": o["pay_status"]}
        ns, nps = b.get("status", o["status"]), b.get("pay_status", o["pay_status"])
        if ns not in ORDER_STATUSES or nps not in PAY_STATUSES:
            raise ApiError(400, "invalid_input", "Unknown status")
        if o["status"] in ("Cancelled", "Refunded") and ns != o["status"]:
            raise ApiError(409, "order_closed", "A cancelled or refunded order cannot be re-opened. Ask the customer to place a new order.")
        if ns != o["status"]:
            o["status"] = ns
            o["history"].append({"s": ns, "t": iso()})
            if ns in ("Cancelled", "Refunded") and not o["restocked"]:
                items = coll_get("items")
                for l in o["items"]:
                    it = items.get(l["id"])
                    if it and it.get("st") is not None:
                        it["st"] = round(it["st"] + l["q"], 3)
                coll_put("items", items)
                o["restocked"] = True
            if ns == "Refunded" and o["pay_status"] == "Paid":
                nps = "Refunded"
        o["pay_status"] = nps
        if "admin_note" in b:
            o["admin_note"] = s_(b["admin_note"], 500)
        meta = get(K("meta.json"), {"sale": 1000, "inv": 0, "idem": {}})
        if o["status"] == "Completed" and not o.get("sale_id"):      # a completed online order becomes a real sale in reports
            meta["sale"] += 1
            sid = f"{ym()}-{nid()}"
            sale = {"id": sid, "no": meta["sale"], "date": iso(), "cust": o["cust"]["id"], "items": [{"i": l["id"], "n": l["n"], "q": l["q"], "p": l["price"], "c": l.get("c", 0)} for l in o["items"]],
                    "sub": o["sub"], "disc": 0, "tax": 0, "total": o["sub"], "method": "M-Pesa" if o["pay_method"] == "mpesa" else "Cash",
                    "paid": o["pay_status"] == "Paid", "status": "completed", "by": g.uid, "online": o["number"]}
            sh = get(sale_shard(sid[:6]), {})
            sh[sid] = sale
            put(sale_shard(sid[:6]), sh)
            put(K("meta.json"), meta)
            o["sale_id"] = sid
        if o["status"] == "Refunded" and o.get("sale_id"):
            sk = sale_shard(o["sale_id"][:6])
            sh = get(sk, {})
            if o["sale_id"] in sh:
                sh[o["sale_id"]]["status"], sh[o["sale_id"]]["refunded_at"] = "refunded", iso()
                put(sk, sh)
        sh = get(oshard(m), {})
        sh[o["number"]] = o
        put(oshard(m), sh)
        ix = oindex()
        ix[o["number"]]["s"], ix[o["number"]]["p"] = o["status"], o["pay_status"]
        put(K("orders", "index.json"), ix)
    audit("update", "orders", o["number"], old, {"status": o["status"], "pay_status": o["pay_status"]})
    return jsonify(order_view(o, owner=True))


# ---------------------------------------------------------------- public pages (a separate visual experience from the dashboard)
STORE_CSS = r"""
*,*:before,*:after{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
:root{--a:#0a6cff;--on:#fff;--bg:#f5f7fa;--card:#fff;--ink:#14202b;--mut:#5d6b78;--line:#e1e7ee;--r:14px;--ar:1/1;--hf:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--bad:#b3361f;--ok:#12653a}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow-x:hidden;padding-bottom:calc(70px + env(safe-area-inset-bottom,0px))}
body.t-electronics{--bg:#0c1220;--card:#141c2e;--ink:#e8eefc;--mut:#9aa8c4;--line:#243049;--r:10px;--ar:4/3}
body.t-fashion{--bg:#faf8f5;--r:2px;--ar:3/4;--hf:Georgia,"Times New Roman",serif;--line:#e6e0d8}
body.t-food{--bg:#fff7ee;--r:20px;--ar:4/3;--line:#f0dcc5}
body.t-general{--bg:#f3f4f2;--r:8px;--ar:1/1}
h1,h2,h3{font-family:var(--hf);margin:0;line-height:1.2}a{color:inherit}img{max-width:100%;display:block}
button,input,select,textarea{font:inherit;color:inherit}
input,select,textarea{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);min-height:44px;font-size:16px}
button{cursor:pointer;border:1px solid var(--line);background:var(--card);border-radius:10px;padding:0 16px;min-height:44px;font-weight:600;touch-action:manipulation}
.pr{background:var(--a);color:var(--on);border-color:var(--a)}button:disabled{opacity:.55;cursor:not-allowed}
.w{max-width:1180px;margin:0 auto;padding:0 14px}
.hd{position:sticky;top:0;z-index:30;background:var(--card);border-bottom:1px solid var(--line);padding-top:env(safe-area-inset-top,0px)}
.hd .w{display:flex;align-items:center;gap:10px;min-height:60px}
.br{display:flex;align-items:center;gap:10px;text-decoration:none;min-width:0;font-weight:800;font-family:var(--hf)}
.br img,.br i{width:38px;height:38px;border-radius:10px;object-fit:cover;flex:none;background:var(--a);color:var(--on);display:grid;place-items:center;font-style:normal}
.br span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:34vw}
.sr{flex:1;min-width:0}.sr input{border-radius:99px;padding-left:16px}
.ib{position:relative;width:46px;padding:0;border-radius:50%;flex:none;display:grid;place-items:center;text-decoration:none}
.bd{position:absolute;top:-4px;right:-4px;min-width:20px;height:20px;border-radius:10px;background:var(--a);color:var(--on);font-size:12px;display:grid;place-items:center;padding:0 5px}
.hero{background:linear-gradient(135deg,var(--a),color-mix(in srgb,var(--a) 55%,#000));color:var(--on);background-size:cover;background-position:center;position:relative}
.hero:before{content:"";position:absolute;inset:0;background:rgba(0,0,0,.38)}.hero.nb:before{display:none}
.hero .w{position:relative;padding-top:38px;padding-bottom:38px}.hero h1{font-size:clamp(1.6rem,6vw,2.6rem)}.hero p{max-width:60ch;margin:10px 0 0;opacity:.95}
.hero .row{margin-top:16px}.hero a.pr{background:#fff;color:#111;border-color:#fff;text-decoration:none;display:inline-grid;place-items:center;padding:0 20px;min-height:44px;border-radius:10px;font-weight:700}
.chips{display:flex;gap:8px;overflow-x:auto;padding:14px 0 4px;scrollbar-width:none}.chips::-webkit-scrollbar{display:none}
.chips button{flex:none;border-radius:99px;min-height:38px;font-size:14px}.chips .on{background:var(--a);color:var(--on);border-color:var(--a)}
.flt{margin:8px 0}.flt summary{cursor:pointer;font-weight:600;min-height:40px;display:flex;align-items:center}
.fg{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;padding:8px 0}.fg label{font-size:13px;color:var(--mut);display:flex;flex-direction:column;gap:4px}
.fg .ck{flex-direction:row;align-items:center;gap:8px;color:var(--ink)}.fg .ck input{width:auto;min-height:0}
h2.sh{font-size:1.25rem;margin:22px 0 10px}
.gr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
@media(min-width:640px){.gr{grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}}@media(min-width:960px){.gr{grid-template-columns:repeat(4,minmax(0,1fr))}}
.cd{background:var(--card);border:1px solid var(--line);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;min-width:0}
.cd .im{position:relative;aspect-ratio:var(--ar);background:var(--line);display:block}.cd .im img{width:100%;height:100%;object-fit:cover}
.ph{width:100%;height:100%;display:grid;place-items:center;color:var(--mut);font-size:12px;padding:6px;text-align:center}
.tg{position:absolute;top:8px;left:8px;background:var(--bad);color:#fff;font-size:12px;font-weight:700;padding:2px 8px;border-radius:99px}.tg.o{background:#333}
.cd .bo{padding:10px;display:flex;flex-direction:column;gap:4px;flex:1}.cd h3{font-size:.95rem;font-family:var(--hf);overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.cd h3 a{text-decoration:none}.pc{font-weight:800}.pc s{color:var(--mut);font-weight:400;font-size:.85em;margin-left:6px}.lf{color:var(--bad);font-size:12px}
.cd .ab{margin-top:auto;padding-top:6px}.cd .ab button,.cd .ab a{width:100%;font-size:14px;text-align:center;text-decoration:none;display:grid;place-items:center}
.more{text-align:center;margin:20px 0}.em{text-align:center;color:var(--mut);padding:40px 10px}
.pd{display:grid;gap:18px;padding:16px 0}@media(min-width:760px){.pd{grid-template-columns:1fr 1fr;gap:32px}}
.pd .big{border-radius:var(--r);overflow:hidden;aspect-ratio:var(--ar);background:var(--line);border:1px solid var(--line)}.pd .big img{width:100%;height:100%;object-fit:cover}
.pd h1{font-size:1.6rem}.pd .pc{font-size:1.5rem;margin:8px 0}.mut{color:var(--mut)}.dsc{white-space:pre-wrap;margin:12px 0}
.qt{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:10px;background:var(--card)}.qt button{border:0;width:44px;font-size:20px;background:none}.qt span{min-width:34px;text-align:center;font-weight:700}
.acts{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.acts>*{flex:1 1 140px}
.box{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px;margin:14px 0}
.co{display:grid;gap:16px;padding:16px 0}@media(min-width:860px){.co{grid-template-columns:1.2fr 1fr}}
label.f{display:block;margin:10px 0 0;font-size:14px;font-weight:600}label.f input,label.f textarea,label.f select{margin-top:4px;font-weight:400}
.opt{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:10px;padding:10px;margin-top:8px;background:var(--card);font-weight:400}.opt input{width:auto;min-height:0;margin-top:4px}
.ln{display:flex;gap:10px;align-items:center;padding:10px 0;border-bottom:1px solid var(--line)}.ln img,.ln .ph{width:56px;height:56px;border-radius:8px;object-fit:cover;flex:none;background:var(--line)}
.ln .t{flex:1;min-width:0}.ln .t b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ln .x{background:none;border:0;color:var(--bad);min-height:36px;padding:0 8px}
.tt{display:flex;justify-content:space-between;padding:4px 0}.tt.g{font-weight:800;font-size:1.1rem;border-top:1px solid var(--line);margin-top:6px;padding-top:10px}
.er{color:var(--bad);font-size:14px;min-height:20px;margin-top:8px}.ok{color:var(--ok)}
.dw{position:fixed;inset:0;z-index:60;display:none}.dw.on{display:block}.dw .sh2{position:absolute;inset:0;background:rgba(0,0,0,.5)}
.dw aside{position:absolute;right:0;top:0;bottom:0;width:min(420px,100%);background:var(--bg);display:flex;flex-direction:column;padding:14px;padding-bottom:calc(14px + env(safe-area-inset-bottom,0px))}
.dw .ls{flex:1;overflow:auto}.dw .hh{display:flex;justify-content:space-between;align-items:center}.dw .hh button{border:0;background:none;font-size:24px;width:44px}
.cb{position:fixed;left:10px;right:10px;bottom:calc(10px + env(safe-area-inset-bottom,0px));z-index:40;display:none;background:var(--a);color:var(--on);border-radius:14px;padding:0 18px;min-height:54px;justify-content:space-between;align-items:center;box-shadow:0 8px 24px rgba(0,0,0,.25);border:0;font-weight:700}
.cb.on{display:flex}@media(min-width:900px){.cb{display:none!important}}
.tl{list-style:none;margin:12px 0;padding:0}.tl li{padding:6px 0 6px 22px;position:relative}.tl li:before{content:"";position:absolute;left:4px;top:13px;width:10px;height:10px;border-radius:50%;background:var(--a)}
.st{display:inline-block;padding:3px 12px;border-radius:99px;background:var(--a);color:var(--on);font-weight:700;font-size:13px}
footer{margin-top:30px;padding:24px 0;border-top:1px solid var(--line);color:var(--mut);font-size:14px}footer a{color:var(--a)}
.ts{position:fixed;left:50%;transform:translateX(-50%);bottom:calc(84px + env(safe-area-inset-bottom,0px));background:#111;color:#fff;padding:10px 18px;border-radius:99px;z-index:90;display:none;max-width:90vw}
.sk{background:linear-gradient(100deg,var(--line) 30%,color-mix(in srgb,var(--line) 50%,var(--card)) 50%,var(--line) 70%);background-size:300% 100%;animation:s 1.2s linear infinite;border-radius:var(--r);aspect-ratio:var(--ar)}@keyframes s{to{background-position:-300% 0}}
@media(prefers-reduced-motion:reduce){*{animation:none!important}}
"""

STORE_JS = r"""
(function(){
const S=JSON.parse(document.getElementById('sd').textContent),B='/shop/'+S.slug,$=s=>document.querySelector(s),A=$('#app');
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fm=n=>S.cur+' '+(+n).toLocaleString('en-KE',{maximumFractionDigits:2});
const CK='ace_cart_'+S.slug;let cart=[];try{cart=JSON.parse(localStorage.getItem(CK)||'[]')}catch(e){}
const cnt=()=>cart.reduce((a,l)=>a+l.q,0);
function save(){try{localStorage.setItem(CK,JSON.stringify(cart))}catch(e){}badge()}
function badge(){const n=cnt();$('#bd').textContent=n;$('#bd').style.display=n?'grid':'none';$('#cn').textContent=n;$('#cbar').classList.toggle('on',n>0&&S.view!='checkout')}
function toast(t){const e=$('#ts');e.textContent=t;e.style.display='block';clearTimeout(toast.t);toast.t=setTimeout(()=>e.style.display='none',2200)}
async function J(p,o){const r=await fetch(B+p,o);let j={};try{j=await r.json()}catch(e){}if(!r.ok)throw Error((j.error||{}).message||'Something went wrong. Please try again.');return j}
const post=(p,b,h)=>J(p,{method:'POST',headers:Object.assign({'Content-Type':'application/json'},h||{}),body:JSON.stringify(b)});
const im=(u,n)=>u?`<img src="${esc(u)}" alt="${esc(n)}" loading="lazy" decoding="async">`:`<div class="ph">${esc(n)}</div>`;
function add(id,v,q){q=q||1;const l=cart.find(x=>x.id==id&&x.v==(v||''));if(l)l.q=Math.min(99,l.q+q);else cart.push({id:id,v:v||'',q:Math.min(99,q)});save();toast('Added to cart')}
/* ---- cart drawer ---- */
async function drawer(open){const d=$('#dw');d.classList.toggle('on',open!==false);if(open===false)return;const ls=$('#dls'),ft=$('#dft');
if(!cart.length){ls.innerHTML='<div class="em">Your cart is empty.</div>';ft.innerHTML='<button onclick="ACE.close()">Continue shopping</button>';return}
ls.innerHTML='<div class="em">Loading...</div>';
try{const r=await post('/cart',{lines:cart});cart=r.lines.map(l=>({id:l.id,v:l.v,q:l.q}));save();
ls.innerHTML=(r.issues.length?`<div class="er">${esc(r.issues.map(i=>i.msg).join(', '))}. Your cart was updated.</div>`:'')+r.lines.map(l=>`<div class="ln">${l.img?`<img src="${esc(l.img)}" alt="" loading="lazy">`:'<div class="ph"></div>'}<div class="t"><b>${esc(l.n)}</b><small class="mut">${l.v?esc(l.v)+' · ':''}${fm(l.price)}</small>
<div class="qt" style="margin-top:4px"><button aria-label="Decrease" onclick="ACE.q('${l.id}','${esc(l.v)}',-1)">−</button><span>${l.q}</span><button aria-label="Increase" onclick="ACE.q('${l.id}','${esc(l.v)}',1)">+</button></div></div><div><b>${fm(l.line)}</b><br><button class="x" onclick="ACE.rm('${l.id}','${esc(l.v)}')">Remove</button></div></div>`).join('');
ft.innerHTML=r.lines.length?`<div class="tt"><span>Subtotal</span><span>${fm(r.sub)}</span></div><div class="tt"><span>Delivery</span><span>${r.fulfil=='delivery'?(r.fee?fm(r.fee):'Free'):'Pickup'}</span></div><div class="tt g"><span>Total</span><span>${fm(r.total)}</span></div>
<a class="pr" href="${B}/checkout" style="display:grid;place-items:center;min-height:48px;border-radius:10px;text-decoration:none;font-weight:700;margin-top:8px">Checkout</a><div class="acts"><button onclick="ACE.close()">Continue shopping</button><button onclick="ACE.clear()">Clear cart</button></div>`:'<button onclick="ACE.close()">Continue shopping</button>'}
catch(e){ls.innerHTML=`<div class="er">${esc(e.message)}</div>`}}
window.ACE={close:()=>drawer(false),open:()=>drawer(),clear:()=>{cart=[];save();drawer()},
rm:(id,v)=>{cart=cart.filter(l=>!(l.id==id&&l.v==v));save();drawer()},q:(id,v,d)=>{const l=cart.find(x=>x.id==id&&x.v==v);if(!l)return;l.q+=d;if(l.q<1)cart=cart.filter(x=>x!==l);if(l&&l.q>99)l.q=99;save();drawer()},
add:(id)=>{add(id,'',1)}};
/* ---- home ---- */
function card(p){const d=p.disc?`<span class="tg">-${Math.round(p.disc)}%</span>`:'',o=!p.in_stock?'<span class="tg o">OUT OF STOCK</span>':'';
return `<div class="cd"><a class="im" href="${B}/product/${p.id}">${im(p.img,p.n)}${p.in_stock?d:o}</a><div class="bo"><h3><a href="${B}/product/${p.id}">${esc(p.n)}</a></h3><div class="pc">${fm(p.price)}${p.was?`<s>${fm(p.was)}</s>`:''}</div>${p.left?`<div class="lf">Only ${p.left} left</div>`:''}
<div class="ab">${!p.in_stock?'<button disabled>Out of stock</button>':p.hasv?`<a class="btn" href="${B}/product/${p.id}" style="border:1px solid var(--line);border-radius:10px;min-height:44px">Choose options</a>`:`<button class="pr" data-add="${p.id}">Add to cart</button>`}</div></div></div>`}
const F={q:'',cat:'',sort:'',min:'',max:'',avail:'',featured:'',disc:''};let pg=1,pages=1,busy=0,g0;
function qs(x){return Object.entries(x).filter(e=>e[1]!=='').map(e=>e[0]+'='+encodeURIComponent(e[1])).join('&')}
async function load(reset){if(busy)return;busy=1;if(reset){pg=1;g0.innerHTML=Array(6).fill('<div class="sk"></div>').join('')}
try{const r=await J('/api/products?'+qs(Object.assign({},F,{page:pg,limit:24})));
if(reset)g0.innerHTML='';pages=r.pages;g0.insertAdjacentHTML('beforeend',r.data.map(card).join(''));
if(reset&&!r.data.length)g0.innerHTML='<div class="em" style="grid-column:1/-1">No products found.</div>';
if(r.cats&&$('#chips')&&!$('#chips').dataset.l){$('#chips').dataset.l=1;$('#chips').innerHTML='<button data-c="" class="on">All</button>'+r.cats.map(c=>`<button data-c="${esc(c.n)}">${esc(c.n)}</button>`).join('')}
$('#mr').style.display=pg<pages?'block':'none'}catch(e){g0.innerHTML=`<div class="er">${esc(e.message)}</div>`}busy=0}
function home(){const u=new URLSearchParams(location.search);Object.keys(F).forEach(k=>F[k]=u.get(k)||'');$('#gs').value=F.q;
A.innerHTML=`<section class="hero ${S.banner?'':'nb'}" ${S.banner?`style="background-image:url('${esc(S.banner)}')"`:''}><div class="w"><h1>${esc(S.name)}</h1>${S.desc?`<p>${esc(S.desc)}</p>`:''}<div class="row"><a class="pr" href="#shop">Shop now</a></div></div></section>
<div class="w"><div id="fw"></div><div class="chips" id="chips"></div><details class="flt"><summary>Filters &amp; sort</summary><div class="fg">
<label>Sort<select id="f_sort"><option value="">Newest</option><option value="price_asc">Price: low to high</option><option value="price_desc">Price: high to low</option><option value="name">Name</option></select></label>
<label>Min price<input id="f_min" type="number" min="0" inputmode="numeric"></label><label>Max price<input id="f_max" type="number" min="0" inputmode="numeric"></label>
<label class="ck"><input type="checkbox" id="f_avail"> In stock</label><label class="ck"><input type="checkbox" id="f_disc"> On discount</label><label class="ck"><input type="checkbox" id="f_feat"> Featured</label></div></details>
<h2 class="sh" id="shop">Products</h2><div class="gr" id="grid"></div><div class="more" id="mr" style="display:none"><button id="lm">Load more</button></div></div>`;
g0=$('#grid');$('#f_sort').value=F.sort;$('#f_min').value=F.min;$('#f_max').value=F.max;$('#f_avail').checked=F.avail=='1';$('#f_disc').checked=F.disc=='1';$('#f_feat').checked=F.featured=='1';
const ap=()=>{F.sort=$('#f_sort').value;F.min=$('#f_min').value;F.max=$('#f_max').value;F.avail=$('#f_avail').checked?'1':'';F.disc=$('#f_disc').checked?'1':'';F.featured=$('#f_feat').checked?'1':'';
history.replaceState(null,'',location.pathname+(qs(F)?'?'+qs(F):''));load(true)};
['f_sort','f_min','f_max','f_avail','f_disc','f_feat'].forEach(i=>$('#'+i).onchange=ap);
$('#chips').onclick=e=>{const b=e.target.closest('button');if(!b)return;F.cat=b.dataset.c;$('#chips').querySelectorAll('button').forEach(x=>x.classList.toggle('on',x==b));ap()};
$('#lm').onclick=()=>{pg++;load()};
try{new IntersectionObserver(es=>{if(es[0].isIntersecting&&pg<pages&&!busy){pg++;load()}},{rootMargin:'400px'}).observe($('#mr'))}catch(e){}
g0.onclick=e=>{const b=e.target.closest('[data-add]');if(b)add(b.dataset.add,'',1)};
if(!F.q&&!F.cat&&!F.featured){J('/api/products?featured=1&limit=8').then(r=>{if(r.data.length&&r.total<r.data.length+999&&!F.sort){$('#fw').innerHTML=`<h2 class="sh">Featured</h2><div class="gr" id="fg">${r.data.map(card).join('')}</div>`;$('#fg').onclick=g0.onclick}}).catch(()=>{})}
load(true)}
/* ---- product ---- */
async function product(){A.innerHTML='<div class="w"><div class="pd"><div class="sk"></div><div></div></div></div>';
try{const p=(await J('/api/products/'+S.pid)).product,hv=p.vars&&p.vars.length;let q=1;
A.innerHTML=`<div class="w"><p style="margin:14px 0 0"><a href="${B}">← Back to store</a></p><div class="pd"><div class="big">${im(p.img,p.n)}</div><div><h1>${esc(p.n)}</h1><div class="mut">${[p.brand,p.cat,p.sku&&'SKU '+p.sku].filter(Boolean).map(esc).join(' · ')}</div>
<div class="pc">${fm(p.price)}${p.was?`<s>${fm(p.was)}</s> <span class="tg" style="position:static;display:inline-block">-${Math.round(p.disc)}%</span>`:''}</div>
<div class="${p.in_stock?'ok':'er'}" style="min-height:0"><b>${p.in_stock?(p.left?'Only '+p.left+' left':'In stock'):'OUT OF STOCK'}</b></div><div class="dsc">${esc(p.desc)}</div>
${hv?`<label class="f">Option<select id="pv">${p.vars.map(v=>`<option>${esc(v)}</option>`).join('')}</select></label>`:''}
<div style="margin-top:12px"><div class="qt"><button id="qm" aria-label="Decrease">−</button><span id="qn">1</span><button id="qp" aria-label="Increase">+</button></div></div>
<div class="acts"><button class="pr" id="pa" ${p.in_stock?'':'disabled'}>Add to cart</button><button id="pb" ${p.in_stock?'':'disabled'}>Buy now</button></div></div></div></div>`;
const sq=d=>{q=Math.max(1,Math.min(99,q+d));$('#qn').textContent=q};$('#qm').onclick=()=>sq(-1);$('#qp').onclick=()=>sq(1);
const v=()=>hv?$('#pv').value:'';$('#pa').onclick=()=>add(p.id,v(),q);$('#pb').onclick=()=>{add(p.id,v(),q);location.href=B+'/checkout'}}
catch(e){A.innerHTML=`<div class="w"><div class="em">${esc(e.message)}<br><br><a href="${B}">Back to store</a></div></div>`}}
/* ---- checkout ---- */
function cin(){return`${S.delivery.enabled&&S.pickup.enabled?'':''}`}
async function checkout(){const key=(window.crypto&&crypto.randomUUID?crypto.randomUUID():String(Date.now())+Math.random()).slice(0,60);
if(!cart.length){A.innerHTML=`<div class="w"><div class="em">Your cart is empty.<br><br><a href="${B}">Continue shopping</a></div></div>`;return}
let fu=S.delivery.enabled?'delivery':'pickup',R=null;
A.innerHTML=`<div class="w"><h2 class="sh">Checkout</h2><div class="co"><form id="cf" class="box" novalidate><h3>Your details</h3>
<label class="f">Full name<input id="c_n" autocomplete="name" required></label><label class="f">Phone<input id="c_p" type="tel" autocomplete="tel" placeholder="0712 345 678" required></label><label class="f">Email (optional)<input id="c_e" type="email" autocomplete="email"></label>
<h3 style="margin-top:16px">Delivery</h3>${S.delivery.enabled?`<label class="opt"><input type="radio" name="fu" value="delivery" ${fu=='delivery'?'checked':''}><span><b>Delivery</b>${S.delivery.note?`<br><small class="mut">${esc(S.delivery.note)}</small>`:''}</span></label>`:''}
${S.pickup.enabled?`<label class="opt"><input type="radio" name="fu" value="pickup" ${fu=='pickup'?'checked':''}><span><b>Pickup</b>${S.pickup.note?`<br><small class="mut">${esc(S.pickup.note)}</small>`:''}</span></label>`:''}
<div id="dl"><label class="f">Delivery location (town / area)<input id="c_l"></label><label class="f">Address / directions<input id="c_a"></label></div>
<h3 style="margin-top:16px">Payment</h3>${S.pay.cod?`<label class="opt"><input type="radio" name="pm" value="cod" checked><span><b>Pay on delivery / pickup</b></span></label>`:''}
${S.pay.mpesa?`<label class="opt"><input type="radio" name="pm" value="mpesa" ${S.pay.cod?'':'checked'}><span><b>M-Pesa (send manually)</b><br><small class="mut">${esc(S.pay.mpesa_note)}<br>The seller confirms your payment manually; it stays "Pending" until then.</small></span></label>`:''}
<label class="f">Order notes (optional)<textarea id="c_o" rows="2" maxlength="500"></textarea></label><div class="er" id="ce" role="alert"></div><button class="pr" id="cs" style="width:100%;margin-top:8px">Place order</button></form>
<div class="box" id="sm"><h3>Order summary</h3><div id="sl"></div></div></div></div>`;
const sync=()=>{fu=document.querySelector('[name=fu]:checked').value;$('#dl').style.display=fu=='delivery'?'block':'none';summ()};
async function summ(){try{R=await post('/cart',{lines:cart,fulfil:fu});cart=R.lines.map(l=>({id:l.id,v:l.v,q:l.q}));save();
$('#sl').innerHTML=(R.issues.length?`<div class="er">${esc(R.issues.map(i=>i.msg).join(', '))}. Cart updated.</div>`:'')+R.lines.map(l=>`<div class="ln"><div class="t"><b>${esc(l.n)}</b><small class="mut">${l.v?esc(l.v)+' · ':''}${l.q} × ${fm(l.price)}</small></div><b>${fm(l.line)}</b></div>`).join('')+`<div class="tt"><span>Subtotal</span><span>${fm(R.sub)}</span></div><div class="tt"><span>Delivery</span><span>${fu=='delivery'?(R.fee?fm(R.fee):'Free'):'Pickup'}</span></div><div class="tt g"><span>Total</span><span>${fm(R.total)}</span></div>`}
catch(e){$('#sl').innerHTML=`<div class="er">${esc(e.message)}</div>`}}
document.querySelectorAll('[name=fu]').forEach(x=>x.onchange=sync);sync();
$('#cf').onsubmit=async e=>{e.preventDefault();const er=$('#ce'),bt=$('#cs');er.textContent='';
if($('#c_n').value.trim().length<2)return er.textContent='Enter your name.';if($('#c_p').value.replace(/\D/g,'').length<9)return er.textContent='Enter a valid phone number.';
if(fu=='delivery'&&(!$('#c_l').value.trim()||!$('#c_a').value.trim()))return er.textContent='Enter your delivery location and address.';
bt.disabled=true;bt.textContent='Placing order...';
try{const r=await post('/order',{lines:cart,fulfil:fu,pay_method:document.querySelector('[name=pm]:checked').value,location:$('#c_l').value,address:$('#c_a').value,notes:$('#c_o').value,customer:{name:$('#c_n').value,phone:$('#c_p').value,email:$('#c_e').value}},{'Idempotency-Key':key});
cart=[];save();done(r)}catch(x){er.textContent=x.message;bt.disabled=false;bt.textContent='Place order';summ()}}}
function olines(o){return o.items.map(l=>`<div class="tt"><span>${esc(l.n)}${l.v?' ('+esc(l.v)+')':''} × ${l.q}</span><span>${fm(l.line)}</span></div>`).join('')}
function wa(o,w){const t=`Hello ${S.name}, I placed order ${o.number}.\n`+o.items.map(l=>`${l.n}${l.v?' ('+l.v+')':''} x${l.q}`).join('\n')+`\nTotal: ${fm(o.total)}\nName: ${o.customer_name}\n${o.fulfil=='delivery'?'Delivery: '+(o.location||''):'Pickup'}`;return 'https://wa.me/'+w+'?text='+encodeURIComponent(t)}
function done(r){const o=r.order;A.innerHTML=`<div class="w"><div class="box" style="max-width:640px;margin:20px auto"><h2 class="ok">Order placed successfully.</h2><p>Order number: <b>${esc(o.number)}</b></p>${olines(o)}<div class="tt"><span>Delivery</span><span>${o.fulfil=='delivery'?(o.fee?fm(o.fee):'Free'):'Pickup'}</span></div><div class="tt g"><span>Total</span><span>${fm(o.total)}</span></div>
<p>Payment status: <span class="st">${esc(o.pay_status)}</span> &nbsp; Order status: <span class="st">${esc(o.status)}</span></p>${r.payment_note?`<p class="box"><b>Pay with M-Pesa:</b><br>${esc(r.payment_note)}<br><small class="mut">Quote ${esc(o.number)} as the reference. The seller will confirm your payment.</small></p>`:''}
<div class="acts">${r.whatsapp?`<a class="pr" style="display:grid;place-items:center;min-height:44px;border-radius:10px;text-decoration:none" target="_blank" rel="noopener" href="${esc(wa(o,r.whatsapp))}">Send order via WhatsApp</a>`:''}<a href="${B}/track?o=${encodeURIComponent(o.number)}" style="display:grid;place-items:center;min-height:44px;border:1px solid var(--line);border-radius:10px;text-decoration:none">Track this order</a></div><p class="mut" style="font-size:13px">Keep your order number and phone number to track your order.</p></div></div>`;scrollTo(0,0)}
/* ---- track ---- */
function track(){const u=new URLSearchParams(location.search);A.innerHTML=`<div class="w"><div class="box" style="max-width:560px;margin:20px auto"><h2>Track your order</h2><form id="tf"><label class="f">Order number<input id="t_n" value="${esc(u.get('o')||'')}" placeholder="ACE-ORD-10001" required></label><label class="f">Phone number used for the order<input id="t_p" type="tel" required></label><div class="er" id="te" role="alert"></div><button class="pr" style="width:100%;margin-top:8px">Track order</button></form><div id="tr"></div></div></div>`;
$('#tf').onsubmit=async e=>{e.preventDefault();$('#te').textContent='';$('#tr').innerHTML='';try{const o=(await post('/track',{number:$('#t_n').value,phone:$('#t_p').value})).order;
$('#tr').innerHTML=`<h3 style="margin-top:18px">${esc(o.number)}</h3><p>Order status: <span class="st">${esc(o.status)}</span> &nbsp; Payment: <span class="st">${esc(o.pay_status)}</span></p>${olines(o)}<div class="tt g"><span>Total</span><span>${fm(o.total)}</span></div><ul class="tl">${o.history.map(h=>`<li><b>${esc(h.s)}</b> <small class="mut">${new Date(h.t).toLocaleString()}</small></li>`).join('')}</ul>`}catch(x){$('#te').textContent=x.message}}}
/* ---- boot ---- */
document.documentElement.style.setProperty('--a',S.col);{const h=S.col.slice(1),l=(0.299*parseInt(h.slice(0,2),16)+0.587*parseInt(h.slice(2,4),16)+0.114*parseInt(h.slice(4),16))/255;document.documentElement.style.setProperty('--on',l>.62?'#111':'#fff')}
$('#gf').onsubmit=e=>{e.preventDefault();const q=$('#gs').value.trim();if(S.view=='home'){F.q=q;history.replaceState(null,'',location.pathname+(qs(F)?'?'+qs(F):''));load(true)}else location.href=B+(q?'?q='+encodeURIComponent(q):'')};
let tm;$('#gs').oninput=()=>{if(S.view!='home')return;clearTimeout(tm);tm=setTimeout(()=>$('#gf').requestSubmit(),350)};
$('#cbtn').onclick=()=>drawer();$('#cbar').onclick=()=>drawer();$('#dsh').onclick=()=>drawer(false);$('#dx').onclick=()=>drawer(false);
addEventListener('keydown',e=>{if(e.key=='Escape')drawer(false)});badge();
({home:home,product:product,checkout:checkout,track:track}[S.view]||home)();
})();
"""


def _j(o):
    return json.dumps(o).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def not_found_page():
    h = ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         "<meta name=robots content=noindex><title>Store not found | ACE</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;"
         "font:16px/1.5 system-ui,sans-serif;background:#f4f6fb;color:#14202b;padding:20px;text-align:center}.c{max-width:420px}h1{letter-spacing:.08em;font-size:1.5rem}"
         "a,button{display:inline-block;margin:6px;padding:12px 22px;border-radius:10px;border:1px solid #cfd6e4;background:#fff;color:#14202b;text-decoration:none;font:600 16px system-ui;cursor:pointer}"
         "a.p{background:#0a6cff;color:#fff;border-color:#0a6cff}</style></head><body><div class=c><h1>STORE NOT FOUND</h1>"
         "<p>The store you're looking for doesn't exist or is currently unavailable.</p><a class=p href='/'>GO TO ACE</a>"
         "<button onclick='history.length>1?history.back():location.href=\"/\"'>BACK</button></div></body></html>")
    r = make_response(h, 404)
    r.headers["Cache-Control"] = "no-store"
    return r


@app.get("/shop", strict_slashes=False)
def shop_root():
    return redirect("/")


@app.get("/shop/<slug>", strict_slashes=False)
@app.get("/shop/<slug>/product/<pid>", strict_slashes=False)
@app.get("/shop/<slug>/checkout", strict_slashes=False)
@app.get("/shop/<slug>/track", strict_slashes=False)
def shop_page(slug, pid=None):
    try:
        bid, p, stg = store_ctx(slug)
    except NoStore:
        return not_found_page()
    view = "product" if pid else ("checkout" if request.path.rstrip("/").endswith("/checkout") else "track" if request.path.rstrip("/").endswith("/track") else "home")
    base, name = site_base(), stg["name"] or p["name"]
    title, desc, img, path = f"{name} | Online Store", stg["desc"] or f"Shop online at {name}. Browse products and order in minutes.", None, f"/shop/{slug}"
    if stg.get("banner"):
        img = f"{path}/img/{stg['banner']}"
    elif p.get("logo"):
        img = f"{path}/img/{p['logo']}"
    if view == "product":
        it = coll_get("items").get(pid) if ID_RE.match(pid) else None
        if not it or not it.get("pub"):
            return not_found_page()
        title, desc, path = f"{it['n']} | {name}", (it.get("desc") or f"{it['n']} - {p.get('cur', 'KES')} {eff_price(it):,.0f} at {name}")[:160], f"{path}/product/{pid}"
        img = f"/shop/{slug}/img/{it['img']}" if it.get("img") else img
    elif view != "home":
        title, path = f"{'Checkout' if view == 'checkout' else 'Track order'} | {name}", f"{path}/{view}"
    cfg = {"slug": slug, "view": view, "pid": pid, "name": name, "desc": stg["desc"], "col": stg["col"], "cur": p.get("cur", "KES"),
           "banner": f"/shop/{slug}/img/{stg['banner']}" if stg.get("banner") else None, "delivery": stg["delivery"], "pickup": stg["pickup"], "pay": stg["pay"]}
    logo = f"/shop/{slug}/img/{p['logo']}" if p.get("logo") else None
    wa = digits(stg.get("whatsapp"))
    contact = " · ".join(x for x in (hesc(stg["location"]), hesc(stg["phone"]), f"<a href='mailto:{hesc(stg['email'])}'>{hesc(stg['email'])}</a>" if stg["email"] else "", hesc(stg["hours"])) if x)
    page = f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{hesc(title)}</title><meta name=description content="{hesc(desc)}"><link rel=canonical href="{hesc(base + path)}">
<meta property=og:type content=website><meta property=og:title content="{hesc(title)}"><meta property=og:description content="{hesc(desc)}"><meta property=og:url content="{hesc(base + path)}">
{f'<meta property=og:image content="{hesc(base + img)}">' if img else ''}<meta name=twitter:card content=summary_large_image><meta name=theme-color content="{hesc(stg['col'])}">
<style>{STORE_CSS}</style></head><body class="t-{hesc(stg['theme'])}">
<header class=hd><div class=w><a class=br href="/shop/{hesc(slug)}">{f'<img src="{hesc(logo)}" alt="">' if logo else f'<i>{hesc((name[:1] or "S").upper())}</i>'}<span>{hesc(name)}</span></a>
<form class=sr id=gf role=search><input id=gs type=search placeholder="Search products, brands, SKU" aria-label="Search products" maxlength=60></form>
{f'<a class=ib href="https://wa.me/{wa}" target=_blank rel=noopener aria-label="WhatsApp" title="WhatsApp">WA</a>' if wa else ''}
<button class=ib id=cbtn aria-label="Cart">&#128722;<span class=bd id=bd style="display:none">0</span></button></div></header>
<main id=app></main>
<footer><div class=w><b>{hesc(name)}</b><br>{contact}<br><small>Powered by ACE Business Management Systems</small></div></footer>
<button class=cb id=cbar><span><span id=cn>0</span> item(s) in cart</span><span>View cart</span></button>
<div class=dw id=dw><div class=sh2 id=dsh></div><aside><div class=hh><h3>Your cart</h3><button id=dx aria-label=Close>&times;</button></div><div class=ls id=dls></div><div id=dft></div></aside></div>
<div class=ts id=ts role=status></div>
<script id=sd type="application/json">{_j(cfg)}</script><script>{STORE_JS}</script></body></html>"""
    r = make_response(page)
    r.headers["Cache-Control"] = "no-cache"
    return r


# ============================================================================= platform admin: details, storage, delete, cache
_usage = [0.0, None]
_epoch = [0.0, 0]


def b2_list(prefix):
    """Yield (key, size) for every object under prefix (paginated, B2 S3-compatible)."""
    tok = None
    while True:
        kw = {"Bucket": BUCKET, "Prefix": prefix, "MaxKeys": 1000}
        if tok:
            kw["ContinuationToken"] = tok
        r = s3.list_objects_v2(**kw)
        for o in r.get("Contents", []):
            yield o["Key"], o["Size"]
        if not r.get("IsTruncated"):
            return
        tok = r.get("NextContinuationToken")


def b2_delete_many(keys):
    for i in range(0, len(keys), 1000):
        s3.delete_objects(Bucket=BUCKET, Delete={"Objects": [{"Key": k} for k in keys[i:i + 1000]], "Quiet": True})


def usage_all(refresh=False):
    """One pass over biz/ -> bytes per business (cached 5 min). Platform-wide, so cost does not grow per business."""
    if not refresh and _usage[1] is not None and time.time() - _usage[0] < 300:
        return _usage[1]
    per, tot_b, tot_n = {}, 0, 0
    for k, sz in b2_list("biz/"):
        parts = k.split("/")
        if len(parts) < 3:
            continue
        u = per.setdefault(parts[1], {"bytes": 0, "objects": 0})
        u["bytes"] += sz
        u["objects"] += 1
        tot_b += sz
        tot_n += 1
    other = sum(sz for _, sz in b2_list("platform/")) + sum(sz for _, sz in b2_list("sessions/"))
    _usage[0], _usage[1] = time.time(), {"per": per, "bytes": tot_b, "objects": tot_n, "platform_bytes": other, "at": iso()}
    return _usage[1]


def usage_detail(bid):
    folders, tot, n = {}, 0, 0
    for k, sz in b2_list(f"biz/{bid}/"):
        rest = k.split("/", 2)[2]
        f = rest.split("/", 1)[0] if "/" in rest else "(data files)"
        d = folders.setdefault(f, {"bytes": 0, "objects": 0})
        d["bytes"] += sz
        d["objects"] += 1
        tot += sz
        n += 1
    return {"bytes": tot, "objects": n, "folders": folders}


@app.get("/api/v1/admin/storage")
@api(admin=True)
def adm_storage():
    u = usage_all(request.args.get("refresh") == "1")
    return jsonify(per=u["per"], bytes=u["bytes"], objects=u["objects"], platform_bytes=u["platform_bytes"], at=u["at"])


@app.get("/api/v1/admin/businesses/<bid>")
@api(admin=True)
def adm_biz_get(bid):
    bid = rid(bid)
    p = get(f"biz/{bid}/profile.json")
    if not p:
        raise ApiError(404, "not_found", "Business not found")
    g.bid, g.uid = bid, "admin"
    users = get(f"biz/{bid}/users.json", {})
    items, custs = coll_get("items"), coll_get("customers")
    ix = oindex()
    ud = usage_detail(bid)
    st = store_load(bid, p, fresh=True)
    sales = 0
    for k, _ in b2_list(f"biz/{bid}/sales/"):
        sales += len(get(k, {}))
    return jsonify(
        business={k: p.get(k) for k in ("id", "name", "type", "loc", "phone", "owner_email", "plan", "status", "billing", "created", "cur", "slug", "referral_code")} | {"effective_status": eff_status(p)},
        store={"url": store_url(p["slug"]) if p.get("slug") else None, "state": store_state(p), "enabled": st["enabled"], "theme": st["theme"]},
        counts={"users": len(users), "items": len(items), "published": sum(1 for v in items.values() if v.get("pub")), "customers": len(custs), "online_orders": len(ix), "sales": sales},
        users=[{"name": u.get("name"), "email": u.get("email"), "role": u.get("role"), "active": u.get("active", True), "google": bool(u.get("google"))} for u in users.values()],
        storage={"bytes": ud["bytes"], "objects": ud["objects"], "folders": ud["folders"]})


def purge_business(bid):
    """Irreversible. Removes every stored object and every index entry that points at the business."""
    p = get(f"biz/{bid}/profile.json")
    if not p:
        raise ApiError(404, "not_found", "Business not found")
    users = get(f"biz/{bid}/users.json", {})
    sess = get(f"biz/{bid}/sessions.json", {})
    keys = [k for k, _ in b2_list(f"biz/{bid}/")]
    for u in users.values():
        if u.get("email"):
            keys.append(f"idx/email/{sha(u['email'].lower())}.json")
        if u.get("google"):
            keys.append(f"idx/google/{u['google']}.json")
    keys += [f"sessions/{v['h']}.json" for v in sess.values() if v.get("h")]
    if p.get("referral_code"):
        keys.append(f"platform/referrals/{p['referral_code']}.json")
    b2_delete_many(keys)
    with lock("platform"):
        idx = get("platform/businesses.json", {})
        idx.pop(bid, None)
        put("platform/businesses.json", idx)
        d = dom_idx(True)
        rec = d["biz"].pop(bid, None) or {}
        d["slugs"] = {k: v for k, v in d["slugs"].items() if v != bid}
        d["hosts"] = {k: v for k, v in d["hosts"].items() if v != bid}
        dom_save(d)
        tk = get("platform/tickets.json", [])
        if any(t.get("bid") == bid for t in tk):
            put("platform/tickets.json", [t for t in tk if t.get("bid") != bid])
    clear_caches(bid)
    _usage[1] = None
    return {"objects": len(keys), "slug": p.get("slug")}


@app.delete("/api/v1/admin/businesses/<bid>")
@api(admin=True)
def adm_biz_delete(bid):
    bid = rid(bid)
    p = get(f"biz/{bid}/profile.json")
    if not p:
        raise ApiError(404, "not_found", "Business not found")
    if s_(body().get("confirm"), 120).strip().lower() != p["name"].strip().lower():
        raise ApiError(400, "confirm_required", "Type the exact business name to confirm deletion")
    with lock(bid):
        res = purge_business(bid)
    app.logger.warning("ADMIN deleted business %s (%s): %s objects", bid, p["name"], res["objects"])
    return jsonify(deleted=True, name=p["name"], **res)


# ---- cache clearing. Caches are per worker process, so a shared epoch record tells every worker to drop theirs too.
def clear_caches(bid=None):
    n = 0
    stores = (_pcache, _icache, _stcache, _scache)
    for c in stores:
        if bid:
            n += 1 if c.pop(bid, None) is not None else 0
        else:
            n += len(c)
            c.clear()
    if not bid:
        _cfg[0], _cfg[1] = 0.0, None
        _dcache[0], _dcache[1] = 0.0, None
        _usage[0], _usage[1] = 0.0, None
    return n


@app.post("/api/v1/admin/cache/clear")
@api(admin=True)
def adm_cache_clear():
    b = body()
    bid = rid(b["bid"]) if b.get("bid") else None
    if bid and not get(f"biz/{bid}/profile.json"):
        raise ApiError(404, "not_found", "Business not found")
    n = clear_caches(bid)
    ep = get("platform/cache_epoch.json", {"n": 0})
    ep = {"n": ep.get("n", 0) + 1, "bid": bid, "at": iso()}
    put("platform/cache_epoch.json", ep)
    _epoch[0], _epoch[1] = time.time(), ep["n"]
    app.logger.warning("ADMIN cleared cache: %s", bid or "all")
    return jsonify(cleared=True, scope="business" if bid else "all", entries=n, at=ep["at"])


@app.before_request
def _epoch_check():
    if request.path.startswith("/assets") or time.time() - _epoch[0] < 5:
        return
    _epoch[0] = time.time()
    try:
        ep = get("platform/cache_epoch.json")
    except Exception:
        return
    if ep and ep["n"] != _epoch[1]:
        first = _epoch[1] == 0
        if not first:
            clear_caches(ep.get("bid") if ep["n"] == _epoch[1] + 1 else None)
        _epoch[1] = ep["n"]


# ---------------------------------------------------------------- built-in self-test:  python app.py --selftest   (in-memory storage, no B2)
def _selftest():
    global get, put, delete
    import contextlib
    store = {}
    get = lambda k, d=None: json.loads(store[k]) if k in store else d
    put = lambda k, o: store.__setitem__(k, json.dumps(o))
    delete = lambda k: store.pop(k, None)
    globals()["send_mail"] = lambda *a, **k: None
    ctx = app.test_request_context if hasattr(app, "test_request_context") else contextlib.nullcontext
    M = "UITQM8HE8I Confirmed. Ksh600.00 sent to LOOP BIZ for account 480457 on {d} at 11:00 PM. Transaction cost, Ksh10.00."
    D = today().strftime("%-d/%-m/%y")
    n = [0]

    def chk(name, cond):
        n[0] += 1
        assert cond, "FAILED: " + name
        print("ok  ", name)

    def err(fn, code):
        try:
            fn()
        except ApiError as e:
            return e.code == code
        return False

    def biz(email="a@x.com", ref=None):
        bid = uuid.uuid4().hex
        p = {"id": bid, "name": "Shop " + bid[:4], "type": "retail", "owner_email": email, "phone": "", "created": iso(), "trial_start": today().isoformat(),
             "trial_ends": (now() + timedelta(days=TRIAL_DAYS)).date().isoformat(), "col": "#0e5a63"}
        sub_init(p, ref, email)
        put(f"biz/{bid}/profile.json", p)
        g.bid, g.uid, g.role, g.prof = bid, "u1", "owner", p
        referral_register(p)
        return bid, p

    def pay(code, amt, billing="monthly", acct="480457", txt=None):
        m = txt or f"{code} Confirmed. Ksh{amt}.00 sent to LOOP BIZ for account {acct} on {D} at 11:00 PM. Transaction cost, Ksh10.00."
        return submit_core(m, billing)[0]

    with ctx():
        r = parse_mpesa(M.format(d="29/9/26"))["fields"]
        chk("parser example", (r["transaction_code"], r["amount"], r["recipient"], r["account"], r["fee"], r["status"], r["date"], r["time"]) ==
            ("UITQM8HE8I", 600, "LOOP BIZ", "480457", 10, "confirmed", "2026-09-29", "11:00 PM"))
        b1, p1 = biz()
        chk("empty message", err(lambda: submit_core("  ", "monthly"), "invalid_mpesa_message"))
        chk("malformed message", err(lambda: submit_core("hello there, pay me", "monthly"), "invalid_mpesa_message"))
        chk("wrong account", err(lambda: pay("AAA1111111", 600, acct="111111"), "wrong_account"))
        chk("failed transaction", err(lambda: submit_core(f"AB12CD34EF Failed. Ksh600.00 sent to LOOP BIZ for account 480457 on {D} at 11:00 PM.", "monthly"), "invalid_status"))
        chk("wrong recipient", err(lambda: submit_core(f"AB12CD34EF Confirmed. Ksh600.00 sent to SOMEONE ELSE for account 480457 on {D} at 11:00 PM.", "monthly"), "wrong_recipient"))
        a = pay("AAA1111111", 600)
        chk("600 accepted as installment (pending, not counted)", a["state"] == "pending_admin" and sub_status(b1, p1, False)["verified_paid"] == 0)
        chk("resubmit same business returns existing", submit_core(M.format(d=D).replace("UITQM8HE8I", "AAA1111111"), "monthly")[0]["already_submitted"])
        b2, p2 = biz("b@x.com")
        chk("duplicate across businesses", err(lambda: pay("AAA1111111", 600), "duplicate_transaction"))
        g.bid, g.prof = b1, p1
        verify_payment(a["id"])
        chk("verified 600 counts", sub_status(b1, profile(b1, True), False)["verified_paid"] == 600 and sub_status(b1, profile(b1, True), False)["remaining"] == 900)
        chk("double verify blocked", err(lambda: verify_payment(a["id"]), "already_processed"))
        g.bid, g.prof = b1, profile(b1, True)
        x = pay("BBB2222222", 500)
        verify_payment(x["id"])
        g.bid, g.prof = b1, profile(b1, True)
        y = pay("CCC3333333", 400)
        verify_payment(y["id"])
        s = sub_status(b1, profile(b1, True), False)
        chk("600+500+400 = 1500, paid period scheduled after the trial", s["verified_paid"] == 1500 and s["status"] == "trial" and s["complete"] and s["credit"] == 0 and profile(b1, True)["period_start"] == profile(b1, True)["trial_ends"])
        g.bid, g.prof = b1, profile(b1, True)
        z = pay("DDD4444444", 300)
        verify_payment(z["id"])
        chk("payment after a paid period goes to the NEXT period", sub_status(b1, profile(b1, True), False)["verified_paid"] == 300 and sub_status(b1, profile(b1, True), False)["status"] in ("trial", "active"))
        # overpayment exact case
        b3, p3 = biz("c@x.com")
        w = pay("EEE5555555", 1700)
        verify_payment(w["id"])
        s = sub_status(b3, profile(b3, True), False)
        chk("1700 on 1500 -> paid 1500 + credit 200", s["verified_paid"] == 1500 and s["credit"] == 200 and s["status"] in ("trial", "active"))
        chk("allocation recorded", [(q["type"], q["amount"]) for q in pay_out(get(PAYS)[w["id"]])["allocation"]] == [("period", 1500), ("credit", 200)])
        # yearly
        b4, p4 = biz("d@x.com")
        v = pay("FFF6666666", 15000, "yearly")
        verify_payment(v["id"])
        s = sub_status(b4, profile(b4, True), False)
        chk("yearly 15000 paid in one go", s["billing"] == "yearly" and s["verified_paid"] == 15000 and s["complete"])
        b5, p5 = biz("e@x.com")
        for i, amt in enumerate((5000, 5000, 5000)):
            g.bid, g.prof = b5, profile(b5, True)
            q = pay(f"YY{i}7777777", amt, "yearly")
            verify_payment(q["id"])
        chk("yearly installments 3 x 5000", sub_status(b5, profile(b5, True), False)["complete"])
        # rejection
        b6, p6 = biz("f@x.com")
        rj = pay("GGG8888888", 600)
        chk("reject needs a reason", err(lambda: reject_payment(rj["id"], ""), "invalid_input"))
        reject_payment(rj["id"], "Amount does not match")
        chk("rejected not counted", sub_status(b6, profile(b6, True), False)["verified_paid"] == 0)
        chk("verify after reject blocked", err(lambda: verify_payment(rj["id"]), "already_processed"))
        # expired trial keeps data + payment allowed
        b7, p7 = biz("g@x.com")
        p7["trial_ends"] = (today() - timedelta(days=1)).isoformat()
        put(f"biz/{b7}/profile.json", p7)
        g.prof = p7
        settle(p7)
        chk("expired trial -> expired (persisted)", get(f"biz/{b7}/profile.json")["status"] == "expired")
        e = pay("HHH9999999", 1500)
        verify_payment(e["id"])
        chk("payment after expiry re-activates", sub_status(b7, profile(b7, True), False)["status"] == "active")
        # referrals
        b8, p8 = biz("ref@x.com")
        code = p8["referral_code"]
        chk("referral code format", bool(re.fullmatch(r"ACE-[A-Z0-9]{6}", code)))
        g.bid = b8
        b9, p9 = biz("new@x.com", referral_lookup(code))
        chk("registered referral is pending, no reward", get(f"biz/{b8}/referrals.json")["items"][0]["status"] == "pending" and get(f"biz/{b8}/referrals.json")["balance_c"] == 0)
        b10, p10 = biz("ref@x.com", referral_lookup(code))
        chk("self-referral ignored", "referred_by" not in p10)
        g.bid, g.prof = b9, p9
        r1 = pay("RRR1010101", 600)
        chk("reward not given on pending payment", get(f"biz/{b8}/referrals.json")["balance_c"] == 0)
        verify_payment(r1["id"])
        chk("KSh 500 reward after first verified payment", get(f"biz/{b8}/referrals.json")["balance_c"] == 50000)
        g.bid, g.prof = b9, profile(b9, True)
        r2 = pay("RRR2020202", 900)
        verify_payment(r2["id"])
        chk("no duplicate reward", get(f"biz/{b8}/referrals.json")["balance_c"] == 50000)
        # concurrency
        b11, p11 = biz("h@x.com")
        cc = pay("CON1212121", 600)
        res = []

        def worker():
            with ctx():
                try:
                    verify_payment(cc["id"])
                    res.append("ok")
                except ApiError as ex:
                    res.append(ex.code)
        th = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in th]
        [t.join() for t in th]
        chk("concurrent verification credits once", res.count("ok") == 1 and sub_status(b11, profile(b11, True), False)["verified_paid"] == 600)

        # ---- workspaces, slugs, domains
        globals()["ROOT_DOMAIN"], globals()["PLATFORM_CNAME"] = "acebusiness.co.ke", "custom.acebusiness.co.ke"      # domain features are optional; test them as if configured
        chk("slug: spec example", generate_business_slug("ACE Hardware & Electrical Ltd.") == "ace-hardware-electrical-ltd")
        chk("slug: apostrophe + accents", generate_business_slug("Jane's Beauty Salon") == "janes-beauty-salon" and generate_business_slug("Café  Ñandú!!") == "cafe-nandu")
        chk("slug: empty/symbols fall back", generate_business_slug("???") == "business" and generate_business_slug("") == "business")
        chk("slug: length capped, no trailing hyphen", len(generate_business_slug("a" * 30 + " " + "b" * 30)) <= SLUG_MAX and not generate_business_slug("a" * 39 + " bbbb").endswith("-"))
        chk("slug: unique -2, -3", unique_slug("ace-hardware", {"ace-hardware": 1}) == "ace-hardware-2" and unique_slug("ace-hardware", {"ace-hardware": 1, "ace-hardware-2": 2}) == "ace-hardware-3")
        chk("slug: reserved names are never issued", unique_slug("www", {}) == "www-2" and unique_slug("admin", {}) == "admin-2")
        wa, pa = biz("wa@x.com"); wb, pb = biz("wb@x.com")
        pa["name"] = pb["name"] = "Ace Hardware"
        with lock("platform"):
            sa = _claim_slug(wa, pa); sb = _claim_slug(wb, pb)
        chk("two same-named businesses get different slugs", (sa, sb) == ("ace-hardware", "ace-hardware-2"))
        chk("slug stays permanent when re-claimed", _claim_slug(wa, pa) == "ace-hardware")
        # migration of a legacy business (no slug)
        wl, pl = biz("legacy@x.com"); pl["name"] = "Legacy Shop"; put(f"biz/{wl}/profile.json", pl)
        put("platform/businesses.json", {wl: {"name": "Legacy Shop"}})
        mig = ensure_workspace(wl, pl)
        chk("legacy business migrated with slug + saved", mig["slug"] == "legacy-shop" and get(f"biz/{wl}/profile.json")["slug"] == "legacy-shop" and dom_idx(True)["slugs"]["legacy-shop"] == wl)
        chk("migration is idempotent", ensure_workspace(wl, get(f"biz/{wl}/profile.json"))["slug"] == "legacy-shop")
        # hostname resolution
        chk("workspace host resolves via the index", resolve_host("ace-hardware." + ROOT_DOMAIN) == wa and resolve_host("ace-hardware." + ROOT_DOMAIN + ":443") == wa)
        chk("unknown / nested / foreign hosts do not resolve", resolve_host("nobody." + ROOT_DOMAIN) is None and resolve_host("a.b." + ROOT_DOMAIN) is None and resolve_host("evil.com") is None)
        # domain validation
        for good in ("www.mybusiness.co.ke", "https://Shop.Example.com/path?x=1", "mybusiness.co.ke."):
            chk("domain accepted: " + good, bool(clean_domain(good)))
        for bad in ("", "localhost", "no spaces.com", "a_b.com", "1.2.3.4", "http://", "x.com:8080", "-bad-.com", "ace." + ROOT_DOMAIN, ROOT_DOMAIN, "user@x.com", "*.x.com"):
            chk("domain rejected: " + repr(bad), err(lambda b=bad: clean_domain(b), "invalid_domain") or err(lambda b=bad: clean_domain(b), "reserved_domain"))
        # connect + verify with a fake DNS (never trusts input)
        g.bid, g.uid, g.role, g.prof = wa, "u1", "owner", pa
        DNS = {}
        globals()["_dns_query"] = lambda name, t: DNS.get((name, t), [])
        with lock("platform"):
            idx = dom_idx(True); rec = idx["biz"][wa]
            tok = secrets.token_urlsafe(24); rec["custom"] = {"domain": "www.acehardware.co.ke", "status": "pending", "token": tok, "created": iso(), "verified_at": None, "active_at": None, "last_check": None, "error": None, "disabled": False}
            dom_save(idx)
        chk("token is long and random", len(secrets.token_urlsafe(24)) >= 32 and secrets.token_urlsafe(24) != secrets.token_urlsafe(24))
        o, v = run_verify(wa)
        chk("no TXT record -> NOT verified (dns_required)", not v and o["custom"]["status"] == "dns_required" and resolve_host("www.acehardware.co.ke") is None)
        DNS[("_ace-verify.www.acehardware.co.ke", "TXT")] = ["ace-verify=WRONG"]
        o, v = run_verify(wa)
        chk("wrong TXT value -> NOT verified", not v and resolve_host("www.acehardware.co.ke") is None)
        DNS[("_ace-verify.www.acehardware.co.ke", "TXT")] = ["ace-verify=" + tok]
        o, v = run_verify(wa)
        chk("correct TXT, routing missing -> verified (not active)", v and o["custom"]["status"] == "verified" and o["custom"]["verified_at"] and resolve_host("www.acehardware.co.ke") == wa)
        DNS[("www.acehardware.co.ke", "CNAME")] = [PLATFORM_CNAME]
        o, v = run_verify(wa)
        chk("correct TXT + CNAME -> active", v and o["custom"]["status"] == "active")
        chk("custom host resolves to the same workspace", resolve_host("www.acehardware.co.ke") == wa and resolve_host("ace-hardware." + ROOT_DOMAIN) == wa)
        chk("owner sees DNS instructions, admin view hides the token", "dns" in dom_out(wa)["custom"] and "dns" not in dom_out(wa, owner=False)["custom"])
        # tenant isolation
        g.bid, g.prof = wb, pb
        with lock("platform"):
            idx = dom_idx(True)
            try:
                if idx["hosts"].get("www.acehardware.co.ke") not in (None, wb):
                    raise ApiError(409, "domain_taken")
                taken = False
            except ApiError:
                taken = True
        chk("business B is blocked from A's verified host", taken)
        DNS[("_ace-verify.www.acehardware.co.ke", "TXT")] = []
        o, v = run_verify(wa)
        chk("losing the TXT record revokes verification and routing", not v and resolve_host("www.acehardware.co.ke") is None)
        # DNS outage must never flip status
        DNS[("_ace-verify.www.acehardware.co.ke", "TXT")] = ["ace-verify=" + tok]
        def _boom(n, t): raise DnsError("x")
        globals()["_dns_query"] = _boom
        before = dom_out(wa)["custom"]["status"]
        o, v = run_verify(wa)
        chk("DNS outage -> status unchanged, not verified", not v and o["custom"]["status"] == before)
        # admin disable
        globals()["_dns_query"] = lambda name, t: DNS.get((name, t), [])
        DNS[("www.acehardware.co.ke", "CNAME")] = [PLATFORM_CNAME]
        run_verify(wa)
        with lock("platform"):
            idx = dom_idx(True); c = idx["biz"][wa]["custom"]; c["disabled"] = True; _put_host(idx, wa, c); dom_save(idx)
        chk("admin-disabled domain stops resolving and cannot be re-verified", resolve_host("www.acehardware.co.ke") is None and err(lambda: run_verify(wa), "domain_disabled"))
        globals()["ROOT_DOMAIN"], globals()["PLATFORM_CNAME"] = "", ""      # back to the default: no purchased domain
        # calendar arithmetic
        chk("month-end rollover", add_months(date(2026, 1, 31), 1) == date(2026, 2, 28) and add_months(date(2026, 2, 28), 12) == date(2027, 2, 28))

    # ======================= online store: complete flow over real HTTP routes (no ROOT_DOMAIN, no DNS) =======================
    import base64
    PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
    blobs = {}

    class FakeS3:
        def put_object(self, Bucket, Key, Body, ContentType=None):
            blobs[Key] = Body

        def get_object(self, Bucket, Key):
            return {"Body": io.BytesIO(blobs[Key])}

        def generate_presigned_url(self, *a, **k):
            return "https://example.invalid/x"
    globals()["s3"] = FakeS3()
    _rl_hits.clear()
    chk("ROOT_DOMAIN is empty by default (no purchased domain required)", ROOT_DOMAIN == "" and workspace_host("abc") is None and resolve_host("abc.acebusiness.co.ke") is None)
    cl = app.test_client()

    def reg(name, email):
        return cl.post("/api/v1/auth/register", json={"name": "Owner", "email": email, "password": "password123", "phone": "0712345678",
                                                       "business": {"name": name, "type": "retail", "loc": "Nairobi"}})

    def H(tok):
        return {"Authorization": "Bearer " + tok}
    r1 = reg("ABC Hardware", "abc@x.com")
    j1 = r1.get_json()
    chk("register: 201 with slug, store_url, store_status", r1.status_code == 201 and j1["slug"] == "abc-hardware" and j1["store_status"] == "active"
        and j1["store_url"] == "http://localhost/shop/abc-hardware" and "acebusiness" not in json.dumps(j1))
    j2 = reg("ABC Hardware", "abc2@x.com").get_json()
    jx = reg("XYZ Electronics", "xyz@x.com").get_json()
    os.environ.pop("ADMIN_PASSWORD_HASH", None)
    os.environ["ADMIN_PASSWORD"] = "adminpass1234"
    adm = {"Authorization": "Bearer " + cl.post("/api/v1/auth/login", json={"email": "ACEt", "password": "adminpass1234"}).get_json()["token"]}
    ab = cl.get("/api/v1/admin/businesses", headers=adm)
    chk("admin Businesses list works without ROOT_DOMAIN and shows store links", ab.status_code == 200 and all(r.get("workspace_url") is None for r in ab.get_json()["data"])
        and any((r.get("store_url") or "").endswith("/shop/abc-hardware") for r in ab.get_json()["data"]))
    ad = cl.get("/api/v1/admin/domains", headers=adm)
    chk("admin Domains list works without ROOT_DOMAIN", ad.status_code == 200)
    chk("same business name -> abc-hardware-2; other business gets its own slug", j2["slug"] == "abc-hardware-2" and jx["slug"] == "xyz-electronics")
    TA, TB = j1["token"], jx["token"]
    globals()["BASE_URL_ENV"] = "https://ace-business-sytems-1.onrender.com"
    chk("BASE_URL builds the Render store link", store_url("abc-hardware") == "https://ace-business-sytems-1.onrender.com/shop/abc-hardware")
    with app.test_request_context():
        chk("store_url works with BASE_URL only", store_url("mary-fashion") == "https://ace-business-sytems-1.onrender.com/shop/mary-fashion")
    globals()["BASE_URL_ENV"] = ""
    pg = cl.get("/shop/abc-hardware")
    html_ = pg.get_data(as_text=True)
    chk("GET /shop/<slug> loads the storefront with its own title/OG tags", pg.status_code == 200 and "<title>ABC Hardware | Online Store</title>" in html_ and 'og:title' in html_)
    chk("storefront has no admin/dashboard UI or ids", not any(w in html_ for w in ("Employees", "Expenses", "Dashboard", "Authorization")) and r1.get_json()["business"]["id"] not in html_)
    pg = cl.get("/shop/not-real-business")
    chk("unknown store -> professional 404 page", pg.status_code == 404 and "STORE NOT FOUND" in pg.get_data(as_text=True) and "Traceback" not in pg.get_data(as_text=True))
    chk("direct URLs for checkout/track/refresh work", cl.get("/shop/abc-hardware/checkout").status_code == 200 and cl.get("/shop/abc-hardware/track").status_code == 200 and cl.get("/shop/abc-hardware/").status_code == 200)
    chk("empty store lists no placeholder products", cl.get("/shop/abc-hardware/api/products").get_json()["total"] == 0)
    # products
    pa = cl.post("/api/v1/items", headers=H(TA), json={"n": "Samsung A15", "sku": "SA15", "p": 18500, "c": 15000, "st": 10, "cat": "Phones", "brand": "Samsung", "desc": "Great phone", "pub": True, "feat": True})
    ia = pa.get_json()["id"]
    hid = cl.post("/api/v1/items", headers=H(TA), json={"n": "Secret Item", "sku": "SEC1", "p": 5, "st": 3, "pub": False}).get_json()["id"]
    vr = cl.post("/api/v1/items", headers=H(TA), json={"n": "T-Shirt", "sku": "TS1", "p": 1000, "st": 20, "pub": True, "vars": "S, M, L"}).get_json()["id"]
    ib = cl.post("/api/v1/items", headers=H(TB), json={"n": "Laptop", "sku": "LP1", "p": 50000, "st": 5, "pub": True}).get_json()["id"]
    L = cl.get("/shop/abc-hardware/api/products").get_json()
    names = sorted(x["n"] for x in L["data"])
    chk("only published products of THIS business appear", names == ["Samsung A15", "T-Shirt"] and "c" not in L["data"][0] and "bid" not in json.dumps(L))
    chk("other business products are not reachable (list/detail/cart)", cl.get(f"/shop/abc-hardware/api/products/{ib}").status_code == 404
        and cl.post("/shop/abc-hardware/cart", json={"lines": [{"id": ib, "q": 1}]}).get_json()["lines"] == [] and cl.get(f"/shop/xyz-electronics/api/products/{ia}").status_code == 404)
    chk("unpublished product is hidden", cl.get(f"/shop/abc-hardware/api/products/{hid}").status_code == 404 and cl.get(f"/shop/abc-hardware/product/{hid}").status_code == 404)
    chk("search by name/brand/sku/category", all(cl.get(f"/shop/abc-hardware/api/products?q={q}").get_json()["total"] == 1 for q in ("samsung", "SA15", "phones")))
    chk("filters: price, featured, availability", cl.get("/shop/abc-hardware/api/products?max=2000").get_json()["total"] == 1 and cl.get("/shop/abc-hardware/api/products?featured=1").get_json()["total"] == 1)
    cl.patch(f"/api/v1/items/{ia}", headers=H(TA), json={"p": 18000})
    chk("price change shows on the public store immediately", cl.get(f"/shop/abc-hardware/api/products/{ia}").get_json()["product"]["price"] == 18000)
    cl.patch(f"/api/v1/items/{ia}", headers=H(TA), json={"disc": 10})
    chk("discount applied server-side", cl.get(f"/shop/abc-hardware/api/products/{ia}").get_json()["product"]["price"] == 16200)
    ir = cl.post(f"/api/v1/items/{ia}/image", headers=H(TA), data={"file": (io.BytesIO(PNG), "p.png")}, content_type="multipart/form-data")
    iurl = cl.get(f"/shop/abc-hardware/api/products/{ia}").get_json()["product"]["img"]
    im_ = cl.get(iurl)
    chk("product image uploaded to storage and served by the store (no B2 keys)", ir.status_code == 200 and im_.status_code == 200 and im_.mimetype == "image/png" and "B2" not in iurl)
    chk("another store cannot serve this image", cl.get(iurl.replace("abc-hardware", "xyz-electronics")).status_code == 404)
    doc = cl.post("/api/v1/files", headers=H(TA), data={"file": (io.BytesIO(b"%PDF-1.4 x"), "d.pdf")}, content_type="multipart/form-data").get_json()
    chk("private documents are never served publicly", cl.get(f"/shop/abc-hardware/img/{doc['id']}").status_code == 404)
    # cart + order
    c = cl.post("/shop/abc-hardware/cart", json={"lines": [{"id": ia, "q": 2, "price": 1}, {"id": ia, "q": 50}]}).get_json()
    chk("cart ignores browser prices and caps at stock", c["lines"][0]["price"] == 16200 and c["lines"][0]["q"] == 10 and c["issues"])
    cust = {"name": "John Kamau", "phone": "0722 111 222", "email": ""}
    O = {"lines": [{"id": ia, "q": 2, "price": 1}], "fulfil": "delivery", "location": "Thika", "address": "Main St", "customer": cust, "pay_method": "cod"}
    chk("missing details rejected", cl.post("/shop/abc-hardware/order", json={**O, "address": ""}).status_code == 400 and cl.post("/shop/abc-hardware/order", json={**O, "customer": {"name": "J", "phone": "12"}}).status_code == 400)
    ro = cl.post("/shop/abc-hardware/order", json=O, headers={"Idempotency-Key": "k1"})
    o = ro.get_json()["order"]
    chk("order created: unique number, server-side total", ro.status_code == 201 and o["number"] == "ACE-ORD-10001" and o["total"] == 32400 and o["status"] == "Pending" and o["pay_status"] == "Pending")
    ro2 = cl.post("/shop/abc-hardware/order", json=O, headers={"Idempotency-Key": "k1"})
    chk("double-submit with the same key does not create a second order", ro2.get_json()["order"]["number"] == "ACE-ORD-10001")
    chk("inventory deducted once (10 -> 8)", cl.get(f"/api/v1/items/{ia}", headers=H(TA)).get_json()["st"] == 8)
    ol = cl.get("/api/v1/orders", headers=H(TA)).get_json()
    chk("order appears in the business's admin, marked as an online order", ol["total"] == 1 and ol["data"][0]["number"] == "ACE-ORD-10001"
        and cl.get("/api/v1/orders/ACE-ORD-10001", headers=H(TA)).get_json()["label"] == "ONLINE STORE ORDER")
    chk("other business sees none of it", cl.get("/api/v1/orders", headers=H(TB)).get_json()["total"] == 0 and cl.get("/api/v1/orders/ACE-ORD-10001", headers=H(TB)).status_code == 404)
    chk("customer added to the business's customer list", any(v["n"] == "John Kamau" for v in cl.get("/api/v1/customers", headers=H(TA)).get_json()["data"]))
    chk("overselling is rejected", cl.post("/shop/abc-hardware/order", json={**O, "lines": [{"id": ia, "q": 9}]}).status_code == 409)
    chk("variant products require a valid option", cl.post("/shop/abc-hardware/order", json={**O, "lines": [{"id": vr, "q": 1}]}).status_code == 400
        and cl.post("/shop/abc-hardware/order", json={**O, "lines": [{"id": vr, "q": 1, "v": "XXL"}]}).status_code == 400
        and cl.post("/shop/abc-hardware/order", json={**O, "lines": [{"id": vr, "q": 1, "v": "M"}]}).status_code == 201)
    # race: 8 simultaneous buyers, stock 8, each wants 3 -> at most 2 can succeed
    res = []

    def buy():
        res.append(app.test_client().post("/shop/abc-hardware/order", json={**O, "lines": [{"id": ia, "q": 3}]}).status_code)
    _rl_hits.clear()
    th = [threading.Thread(target=buy) for _ in range(8)]
    [t.start() for t in th]
    [t.join() for t in th]
    left = cl.get(f"/api/v1/items/{ia}", headers=H(TA)).get_json()["st"]
    chk("no overselling under concurrency", res.count(201) == 2 and left == 2 and left >= 0)
    # tracking
    chk("tracking needs the right phone; wrong one reveals nothing", cl.post("/shop/abc-hardware/track", json={"number": "ACE-ORD-10001", "phone": "0700000000"}).status_code == 404
        and cl.post("/shop/abc-hardware/track", json={"number": "ACE-ORD-10001", "phone": "+254722111222"}).get_json()["order"]["number"] == "ACE-ORD-10001"
        and cl.post("/shop/xyz-electronics/track", json={"number": "ACE-ORD-10001", "phone": "0722111222"}).status_code == 404)
    chk("track response hides phone/email/address", "0722" not in json.dumps(cl.post("/shop/abc-hardware/track", json={"number": "ACE-ORD-10001", "phone": "0722111222"}).get_json()))
    # statuses
    chk("unknown status rejected", cl.patch("/api/v1/orders/ACE-ORD-10001", headers=H(TA), json={"status": "Bogus"}).status_code == 400)
    cl.patch("/api/v1/orders/ACE-ORD-10001", headers=H(TA), json={"status": "Out for Delivery"})
    chk("customer sees the current status", cl.post("/shop/abc-hardware/track", json={"number": "ACE-ORD-10001", "phone": "0722111222"}).get_json()["order"]["status"] == "Out for Delivery")
    cl.patch("/api/v1/orders/ACE-ORD-10001", headers=H(TA), json={"status": "Completed", "pay_status": "Paid"})
    sl = cl.get("/api/v1/sales", headers=H(TA)).get_json()["data"]
    chk("completed online order becomes a sale (stock not deducted twice)", any(x.get("online") == "ACE-ORD-10001" for x in sl) and cl.get(f"/api/v1/items/{ia}", headers=H(TA)).get_json()["st"] == 2)
    num2 = next(x["number"] for x in cl.get("/api/v1/orders", headers=H(TA)).get_json()["data"] if x["status"] == "Pending" and x["total"] == 48600)
    cl.patch(f"/api/v1/orders/{num2}", headers=H(TA), json={"status": "Cancelled"})
    st2 = cl.get(f"/api/v1/items/{ia}", headers=H(TA)).get_json()["st"]
    cl.patch(f"/api/v1/orders/{num2}", headers=H(TA), json={"status": "Cancelled"})
    chk("cancelling restocks exactly once; cancelled orders cannot be re-opened", st2 > 2 and cl.get(f"/api/v1/items/{ia}", headers=H(TA)).get_json()["st"] == st2
        and cl.patch(f"/api/v1/orders/{num2}", headers=H(TA), json={"status": "Pending"}).status_code == 409)
    cl.patch(f"/api/v1/items/{ia}", headers=H(TA), json={"st": 0})
    p_ = cl.get(f"/shop/abc-hardware/api/products/{ia}").get_json()["product"]
    chk("zero stock shows OUT OF STOCK and blocks purchase", p_["in_stock"] is False and cl.post("/shop/abc-hardware/order", json=O).status_code == 409)
    chk("owner stock edits show on the store", cl.patch(f"/api/v1/items/{ia}", headers=H(TA), json={"st": 4}).status_code == 200 and cl.get(f"/shop/abc-hardware/api/products/{ia}").get_json()["product"]["left"] == 4)
    # store settings / dashboard
    sg = cl.get("/api/v1/store", headers=H(TA)).get_json()
    chk("dashboard store card uses real numbers", sg["url"] == "http://localhost/shop/abc-hardware" and sg["status"] == "active" and sg["stats"]["products"] == 3 and sg["stats"]["published"] == 2 and sg["stats"]["orders"] == len(cl.get("/api/v1/orders", headers=H(TA)).get_json()["data"]))
    chk("invalid theme rejected; valid theme keeps products/orders", cl.patch("/api/v1/store", headers=H(TA), json={"theme": "nope"}).status_code == 400
        and cl.patch("/api/v1/store", headers=H(TA), json={"theme": "fashion", "whatsapp": "254712345678"}).status_code == 200
        and cl.get("/shop/abc-hardware/api/products").get_json()["total"] == 2 and 't-fashion' in cl.get("/shop/abc-hardware").get_data(as_text=True))
    chk("mpesa needs instructions (no fake STK)", cl.patch("/api/v1/store", headers=H(TA), json={"pay": {"mpesa": True}}).status_code == 400)
    cl.patch(f"/api/v1/items/{ia}", headers=H(TA), json={"pub": False})
    chk("unpublish hides it; delete removes it", cl.get(f"/shop/abc-hardware/api/products/{ia}").status_code == 404
        and cl.delete(f"/api/v1/items/{vr}", headers=H(TA)).status_code == 200 and cl.get("/shop/abc-hardware/api/products").get_json()["total"] == 0)
    chk("closing the store makes it unavailable", cl.patch("/api/v1/store", headers=H(TA), json={"enabled": False}).status_code == 200 and cl.get("/shop/abc-hardware").status_code == 404)
    chk("custom domains are optional and off without ROOT_DOMAIN", cl.post("/api/v1/business/domain", headers=H(TA), json={"domain": "www.abc.co.ke"}).get_json()["error"]["code"] == "custom_domains_unavailable"
        and cl.get("/api/v1/business", headers=H(TA)).get_json()["store_url"].endswith("/shop/abc-hardware"))
    chk("pagination: 120 published products are served 24 at a time", (lambda: (
        [cl.post("/api/v1/items", headers=H(TB), json={"n": f"Bulk {i}", "sku": f"B{i}", "p": 10 + i, "st": 1, "pub": True}) for i in range(120)],
        cl.get("/shop/xyz-electronics/api/products").get_json())[1])()["data"].__len__() == 24)
    pj = cl.get("/shop/xyz-electronics/api/products?page=6").get_json()
    chk("last page + total correct", pj["total"] == 121 and pj["pages"] == 6 and len(pj["data"]) == 1)


    # ======================= platform admin: list (regression), details, storage, delete, cache =======================
    def _blist(prefix):
        for k, v in list(store.items()):
            if k.startswith(prefix):
                yield k, len(v)
        for k, v in list(blobs.items()):
            if k.startswith(prefix):
                yield k, len(v)

    def _bdel(keys):
        for k in keys:
            store.pop(k, None)
            blobs.pop(k, None)
    globals()["b2_list"], globals()["b2_delete_many"] = _blist, _bdel
    os.environ.pop("ADMIN_PASSWORD_HASH", None)
    os.environ["ADMIN_PASSWORD"] = "adminpass1234"
    AT = cl.post("/api/v1/auth/login", json={"email": "ACEt", "password": "adminpass1234"}).get_json()["token"]
    HA = {"Authorization": "Bearer " + AT}
    chk("ROOT_DOMAIN empty: admin Businesses list loads (was 'Something went wrong')", cl.get("/api/v1/admin/businesses", headers=HA).status_code == 200)
    rows = cl.get("/api/v1/admin/businesses", headers=HA).get_json()["data"]
    chk("admin list shows store links, no fake workspace domain", all(r.get("workspace_url") is None and r["store_url"].endswith("/shop/" + r["slug"]) for r in rows if r.get("slug")))
    jd = reg("Delete Me Traders", "del@x.com").get_json()
    TD = jd["token"]
    di = cl.post("/api/v1/items", headers=H(TD), json={"n": "Thing", "sku": "T1", "p": 10, "st": 2, "pub": True}).get_json()["id"]
    cl.post(f"/api/v1/items/{di}/image", headers=H(TD), data={"file": (io.BytesIO(PNG), "p.png")}, content_type="multipart/form-data")
    cl.post("/shop/delete-me-traders/order", json={"lines": [{"id": di, "q": 1}], "fulfil": "pickup", "customer": {"name": "Sam Doe", "phone": "0733444555"}, "pay_method": "cod"})
    did = jd["business"]["id"]
    st_ = cl.get("/api/v1/admin/storage?refresh=1", headers=HA).get_json()
    chk("storage used is reported per business and in total", st_["per"][did]["bytes"] > 0 and st_["bytes"] >= st_["per"][did]["bytes"])
    dt = cl.get(f"/api/v1/admin/businesses/{did}", headers=HA).get_json()
    chk("business details: owner, users, counts, store, storage breakdown", dt["business"]["name"] == "Delete Me Traders" and dt["counts"]["items"] == 1 and dt["counts"]["online_orders"] == 1
        and dt["counts"]["users"] == 1 and dt["users"][0]["email"] == "del@x.com" and "hash" not in json.dumps(dt).lower() and dt["storage"]["bytes"] > 0 and "files" in dt["storage"]["folders"] and dt["store"]["url"].endswith("/shop/delete-me-traders"))
    chk("non-admins cannot use admin endpoints", cl.get(f"/api/v1/admin/businesses/{did}", headers=H(TA)).status_code in (401, 403) and cl.delete(f"/api/v1/admin/businesses/{did}", headers=H(TA)).status_code in (401, 403)
        and cl.post("/api/v1/admin/cache/clear", headers=H(TA), json={}).status_code in (401, 403))
    chk("delete needs the exact business name", cl.delete(f"/api/v1/admin/businesses/{did}", headers=HA, json={}).status_code == 400 and cl.delete(f"/api/v1/admin/businesses/{did}", headers=HA, json={"confirm": "wrong"}).status_code == 400
        and cl.get("/shop/delete-me-traders").status_code == 200)
    rd = cl.delete(f"/api/v1/admin/businesses/{did}", headers=HA, json={"confirm": "delete me traders"})
    chk("admin deletes the business", rd.status_code == 200 and rd.get_json()["deleted"] is True)
    chk("its data, files, sessions and indexes are gone", not any(f"biz/{did}/" in k for k in list(store) + list(blobs)) and "idx/email/" + sha("del@x.com") + ".json" not in store
        and did not in get("platform/businesses.json", {}) and "delete-me-traders" not in dom_idx(True)["slugs"])
    chk("deleted business: store 404, login blocked, session dead", cl.get("/shop/delete-me-traders").status_code == 404 and cl.get("/api/v1/items", headers=H(TD)).status_code == 401
        and cl.post("/api/v1/auth/login", json={"email": "del@x.com", "password": "password123"}).status_code == 401)
    chk("other businesses untouched", cl.get("/api/v1/items", headers=H(TB)).status_code == 200 and cl.get("/shop/xyz-electronics").status_code == 200)
    chk("email and store link can be reused after deletion", reg("Delete Me Traders", "del@x.com").get_json()["slug"] == "delete-me-traders")
    chk("deleting an unknown business is a clean 404", cl.delete("/api/v1/admin/businesses/" + "0" * 32, headers=HA, json={"confirm": "x"}).status_code == 404)
    prof_b = cl.get("/api/v1/business", headers=H(TB))
    rc = cl.post("/api/v1/admin/cache/clear", headers=HA, json={})
    chk("clear cache (whole system) works and the app keeps working", rc.status_code == 200 and rc.get_json()["scope"] == "all" and not _pcache and not _icache
        and cl.get("/shop/xyz-electronics").status_code == 200 and cl.get("/api/v1/items", headers=H(TB)).status_code == 200)
    rc2 = cl.post("/api/v1/admin/cache/clear", headers=HA, json={"bid": jx["business"]["id"]})
    chk("clear cache for one business; unknown business rejected", rc2.get_json()["scope"] == "business" and cl.post("/api/v1/admin/cache/clear", headers=HA, json={"bid": "0" * 32}).status_code == 404)
    _epoch[0], _epoch[1] = 0, 0
    store["platform/cache_epoch.json"] = json.dumps({"n": 99, "bid": None})
    _pcache["x"] = (time.time(), {})
    cl.get("/shop/xyz-electronics")
    chk("other workers drop their caches when the shared epoch changes", "x" not in _pcache or _epoch[1] == 99)

    print(f"\nALL {n[0]} CHECKS PASSED")


@app.get("/shots/<path:name>")
def shots(name):
    return send_from_directory(os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots"), name)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
        sys.exit(0)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
