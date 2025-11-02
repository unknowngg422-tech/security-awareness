# app.py
import os
import re
import ssl
import json
import uuid
import random
import hashlib
import sqlite3
import urllib.parse
import urllib.request
from datetime import datetime, timezone, date, timedelta

from flask import (
    Flask, render_template, request, jsonify, session, g, url_for, redirect
)
from werkzeug.security import generate_password_hash, check_password_hash

# --- Monitor imports ---
from flask import Blueprint
from datetime import timedelta as dt_timedelta
import time

# =========================================================
# ================ App & Config ===========================
# =========================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

# !! غيّري السر هذا لقيمة عشوائية طويلة في الإنتاج
app.secret_key = "CHANGE_ME_SECRET_KEY_!@#_RANDOM"

# إعدادات كوكيز السيشن (أمان)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",   # غيّريها "Strict" حسب حاجتك
    SESSION_COOKIE_SECURE=False      # اجعليها True خلف HTTPS
)

# ⚠️: سلوك بدء التشغيل: احذف قاعدة البيانات القديمة تلقائيًا (لتبدأ من الصفر).
# غيّريه إلى False إذا تريدين تعطيله.
RESET_DB_ON_START = False

DB_PATH = os.path.join(BASE_DIR, "database.db")

# =============== Admin Password ===============
# غيّريها لشي قوي
ADMIN_PASSWORD = "MySecret123"

# =========================================================
# ================ DB Helpers =============================
# =========================================================

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    # return rows as tuples (default) — كافي لهذا المشروع
    return conn

def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _client_ip():
    return (request.headers.get("X-Forwarded-For", request.remote_addr or "-")
            .split(",")[0].strip())

# =========================================================
# ================ Schema Init ============================
# =========================================================

def init_core_tables():
    """Core domain tables (password/url/email/quiz logs)."""
    with get_conn() as conn:
        # Password tests
        conn.execute("""
        CREATE TABLE IF NOT EXISTS password_tests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT NULL,
            score      INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            length     INTEGER NOT NULL,
            has_upper  INTEGER NOT NULL,
            has_lower  INTEGER NOT NULL,
            has_digit  INTEGER NOT NULL,
            has_symbol INTEGER NOT NULL,
            is_pwned   INTEGER NOT NULL DEFAULT 0,
            pwn_count  INTEGER NOT NULL DEFAULT 0
        );
        """)

        # URL checks
        conn.execute("""
        CREATE TABLE IF NOT EXISTS url_checks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT NULL,
            created_at TEXT NOT NULL,
            url_hash   TEXT NOT NULL,
            hostname   TEXT,
            verdict    TEXT NOT NULL,
            score      INTEGER NOT NULL,
            reasons    TEXT
        );
        """)

        # Email checks
        conn.execute("""
        CREATE TABLE IF NOT EXISTS email_checks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT NULL,
            created_at TEXT NOT NULL,
            sender     TEXT,
            subject    TEXT,
            verdict    TEXT NOT NULL,
            score      INTEGER NOT NULL,
            reasons    TEXT
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_email_created ON email_checks(created_at);")

        # Quiz attempts
        conn.execute("""
        CREATE TABLE IF NOT EXISTS quiz_attempts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT NULL,
            score      INTEGER NOT NULL,
            total      INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            detail_json TEXT
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quiz_created ON quiz_attempts(created_at);")

def init_login_monitoring():
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            ip         TEXT,
            user_agent TEXT,
            success    INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            reason     TEXT,
            pw_similarity REAL,
            risk_label TEXT
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_created ON login_attempts(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_user ON login_attempts(username);")

def init_users_and_gamify():
    """Users + points + events. Points only for authenticated users."""
    with get_conn() as conn:
        # Users (username + hashed PIN)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            pin_hash   TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen  TEXT,
            role       TEXT NOT NULL DEFAULT 'public',
            deleted_at TEXT
        );
        """)

        # User points (FK to users)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_points (
            user_id     INTEGER PRIMARY KEY,
            points      INTEGER NOT NULL DEFAULT 0,
            level       INTEGER NOT NULL DEFAULT 1,
            streak_days INTEGER NOT NULL DEFAULT 0,
            last_daily  TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # Point events (auditing / badges)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS point_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            kind       TEXT NOT NULL,
            amount     INTEGER NOT NULL,
            meta       TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user_time ON point_events(user_id, created_at);")

# =========================================================
# ================ Request/User Helpers ===================
# =========================================================

@app.before_request
def load_user():
    """
    g.user_id = INTEGER id of users.id when logged in.
    If not logged in, g.user_id = None (guest).
    """
    uid = session.get("uid")
    g.user_id = uid if isinstance(uid, int) else None

def _current_username() -> str | None:
    if not isinstance(getattr(g, "user_id", None), int):
        return None
    try:
        with get_conn() as conn:
            row = conn.execute("SELECT username FROM users WHERE id=?", (g.user_id,)).fetchone()
            return row[0] if row else None
    except Exception:
        return None

def _is_admin() -> bool:
    return getattr(g, "role", "public") == "admin"

def _level_for(points: int) -> int:
    return max(1, 1 + points // 200)

def _get_or_create_user_points(user_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        row = cur.execute(
            "SELECT points, level, streak_days, last_daily FROM user_points WHERE user_id=?",
            (user_id,)
        ).fetchone()
        if not row:
            cur.execute(
                "INSERT INTO user_points (user_id, points, level, streak_days, last_daily) VALUES (?,?,?,?,?)",
                (user_id, 0, 1, 0, None)
            )
            points, level, streak, last_daily = 0, 1, 0, None
        else:
            points, level, streak, last_daily = row
    return points, level, streak, last_daily

def _update_user_points(user_id: int, points: int, level: int, streak: int, last_daily: str|None):
    with get_conn() as conn:
        conn.execute("""
            UPDATE user_points SET points=?, level=?, streak_days=?, last_daily=? WHERE user_id=?;
        """, (points, level, streak, last_daily, user_id))

def _append_point_event(user_id: int, amount: int, kind: str, meta: dict|None = None):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO point_events (user_id, kind, amount, meta, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, kind, amount, json.dumps(meta or {}, ensure_ascii=False), _utcnow()))

def _grant_points(amount: int, kind: str, meta: dict|None = None) -> bool:
    if not isinstance(g.user_id, int) or g.user_id <= 0:
        return False

    with get_conn() as conn:
        row = conn.execute("SELECT id FROM users WHERE id=?", (g.user_id,)).fetchone()
    if not row:
        return False

    points, level, streak, last_daily = _get_or_create_user_points(g.user_id)
    amount = max(0, int(amount or 0))
    points += amount
    level = _level_for(points)

    _update_user_points(g.user_id, points, level, streak, last_daily)
    _append_point_event(g.user_id, amount, kind, meta)
    return True

@app.before_request
def load_role():
    g.role = "public"
    g.user_id = None

    try:
        # ✅ لو المستخدم داخل الجلسة نحمل بياناته
        if "uid" in session:
            g.user_id = session["uid"]

            # ✅ نجيب الدور الحقيقي من قاعدة البيانات
            with get_conn() as conn:
                row = conn.execute("SELECT role FROM users WHERE id=?", (g.user_id,)).fetchone()
                if row and row[0]:
                    g.role = row[0]
    except Exception as e:
        print("⚠️ load_role error:", e)


def _is_staff():
    return getattr(g, "role", "public") in ("staff", "admin")

@app.before_request
def guard_staff_only_views():
    staff_only_endpoints = {"login_monitor"}
    try:
        if request.endpoint in staff_only_endpoints and not _is_staff():
            return ("الصفحة غير موجودة", 404)
    except Exception:
        pass

@app.before_request
def _ensure_role_column_once():
    if app.config.get("_ROLE_COL_DONE"):
        return
    try:
        with get_conn() as conn:
            cur = conn.execute("PRAGMA table_info(users);")
            cols = [r[1] for r in cur.fetchall()]
            if "role" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'public';")
    except Exception:
        pass
    app.config["_ROLE_COL_DONE"] = True

# =========================================================
# ================ Auth (Register/Login/Logout) ===========
# =========================================================

@app.post("/api/auth/register")
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    pin      = (data.get("pin") or "").strip()

    if not re.match(r"^[A-Za-z0-9_\.]{3,16}$", username or ""):
        return jsonify({"ok": False, "error": "٣–١٦ حرفًا/رقمًا/نقطة/شرطة سفلية فقط"}), 400
    if not pin or len(pin) < 4 or len(pin) > 10:
        return jsonify({"ok": False, "error": "PIN غير صالح"}), 400

    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (username, pin_hash, created_at, role) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(pin), _utcnow(), "public")
            )
            row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            uid = int(row[0])
            conn.execute(
                "INSERT OR IGNORE INTO user_points (user_id, points, level, streak_days, last_daily) VALUES (?,?,?,?,?)",
                (uid, 0, 1, 0, None)
            )
        session["uid"] = uid
        session["username"] = username

        return jsonify({"ok": True, "user_id": uid, "username": username})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "الاسم مستخدم"}), 409

def _login_window_status(ip: str, username: str | None, minutes=10, fail_threshold=5):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE success=0 AND ip=? AND created_at >= datetime('now', ?)
        """, (ip, f"-{minutes} minutes"))
        fails_ip = int(cur.fetchone()[0])
        cur.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE success=0 AND username=? AND created_at >= datetime('now', ?)
        """, ((username or ""), f"-{minutes} minutes"))
        fails_user = int(cur.fetchone()[0])
    over = max(fails_ip, fails_user) >= fail_threshold
    cooldown = 60 if over else 0
    return over, cooldown

@app.post("/api/auth/login")
def api_login_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    pin      = (data.get("pin") or "").strip()
    ip = request.remote_addr or "unknown"

    over, cooldown = _login_window_status(ip, username)

    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, pin_hash, role FROM users WHERE username=?", (username,)
        ).fetchone()

    ok = False
    if row:
        stored_hash = row[1]
        try:
            if check_password_hash(stored_hash, pin):
                ok = True
        except Exception:
            ok = False

    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO login_attempts (username, ip, user_agent, success, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (username, ip, request.headers.get("User-Agent", "-"), 1 if ok else 0, _utcnow()))
    except Exception:
        pass

    if not ok:
        return jsonify({"ok": False, "error": "بيانات الدخول غير صحيحة"}), 401

    uid = int(row[0])
    role = row[2] if len(row) > 2 else "public"

    # ✅ اجعل هذا المستخدم أدمن تلقائيًا لو كان اسمه يطابق حسابك
    if username.lower() == "bnoo":
        with get_conn() as conn:
            conn.execute("UPDATE users SET role='admin' WHERE id=?", (uid,))
        role = "admin"

    session["uid"] = uid
    session["username"] = username
    session["role"] = role

    with get_conn() as conn:
        conn.execute("UPDATE users SET last_seen=? WHERE id=?", (_utcnow(), uid))
        conn.execute("""
            INSERT OR IGNORE INTO user_points (user_id, points, level, streak_days, last_daily)
            VALUES (?, ?, ?, ?, ?)
        """, (uid, 0, 1, 0, None))

    return jsonify({
        "ok": True,
        "user_id": uid,
        "username": username,
        "role": role,
        "redirect": "/profile"
    })

@app.post("/api/auth/logout")
def api_logout_user():
    session.pop("uid", None)
    session.pop("username", None)
    session.pop("role", None)
    return jsonify({"ok": True})

@app.get("/api/auth/session")
def api_auth_session():
    uid = session.get("uid")
    username = session.get("username")
    if uid and username:
        return jsonify({
            "logged_in": True,
            "user_id": uid,
            "username": username
        })
    else:
        return jsonify({
            "logged_in": False
        })

# =========================================================
# ================ Gamification APIs ======================
# =========================================================

@app.get("/api/gamify/status")
def api_gamify_status():
    if not isinstance(g.user_id, int):
        return jsonify({
            "is_guest": True,
            "user_id": None,
            "username": None,
            "points": 0,
            "level": 1,
            "streak": 0,
            "next_level_at": 200,
            "progress_pct": 0
        }), 200

    with get_conn() as conn:
        user_row = conn.execute("SELECT username FROM users WHERE id=?", (g.user_id,)).fetchone()
        username = user_row[0] if user_row else None

    points, level, streak, last_daily = _get_or_create_user_points(g.user_id)

    current_level = _level_for(points)
    next_level_at = current_level * 200
    prev_level_at = (current_level - 1) * 200
    progress = 0 if next_level_at == prev_level_at else int(
        100 * (points - prev_level_at) / (next_level_at - prev_level_at)
    )
    return jsonify({
        "is_guest": False,
        "user_id": g.user_id,
        "username": username,
        "points": points,
        "level": current_level,
        "streak": streak,
        "next_level_at": next_level_at,
        "progress_pct": max(0, min(100, progress))
    }), 200

@app.post("/api/gamify/claim-daily")
def api_claim_daily():
    if not isinstance(g.user_id, int):
        return jsonify({"ok": False, "error": "سجّل دخول"}), 401

    today = date.today()
    today_iso = today.isoformat()

    points, level, streak, last_daily = _get_or_create_user_points(g.user_id)

    if last_daily == today_iso:
        return jsonify({"ok": False, "error": "مُحصّل اليوم"}), 409

    if last_daily:
        try:
            prev = date.fromisoformat(last_daily)
            if prev == today - timedelta(days=1):
                streak += 1
            else:
                streak = 1
        except Exception:
            streak = 1
    else:
        streak = 1

    bonus = 5 + min(10, streak)
    points += bonus
    level = _level_for(points)
    _update_user_points(g.user_id, points, level, streak, today_iso)
    _append_point_event(g.user_id, bonus, "daily", {"streak": streak})

    return jsonify({"ok": True, "bonus": bonus, "streak": streak})

# =========================================================
# ================ Security Analysis: Passwords ===========
# =========================================================

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except Exception:
    ZXCVBN_AVAILABLE = False

def simple_fallback_score(pw: str):
    length     = len(pw)
    has_upper  = bool(re.search(r"[A-Z]", pw))
    has_lower  = bool(re.search(r"[a-z]", pw))
    has_digit  = bool(re.search(r"\d", pw))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", pw))

    classes = sum([has_upper, has_lower, has_digit, has_symbol])
    score = 0
    if length >= 8:  score = 1
    if length >= 10 and classes >= 2: score = 2
    if length >= 12 and classes >= 3: score = 3
    if length >= 14 and classes == 4: score = 4

    crack = ["ثوانٍ", "دقائق", "ساعات", "أيام", "سنوات"][min(score, 4)]
    feedback = {
        "warning": "" if score >= 3 else "كلمة المرور أضعف من الموصى به.",
        "suggestions": [
            "استخدم طول 12 حرفًا فأكثر.",
            "اخلط أحرفًا كبيرة/صغيرة وأرقامًا ورموزًا.",
            "تجنّب الكلمات الشائعة والتكرار.",
            "لا تُعِد استخدام كلمة المرور نفسها في أكثر من موقع."
        ]
    }
    return score, crack, feedback

_CRACK_MAP = {
    "less than a second": "أقل من ثانية",
    "seconds": "ثوانٍ",
    "minutes": "دقائق",
    "hours": "ساعات",
    "days": "أيام",
    "months": "أشهر",
    "years": "سنوات",
    "centuries": "قرون",
}

def _translate_crack_time(en: str) -> str:
    if not en:
        return "غير معروف"
    out = en
    for k, v in _CRACK_MAP.items():
        out = out.replace(k, v)
    return out

def _translate_feedback(feedback: dict) -> dict:
    warning = feedback.get("warning") or ""
    suggestions = feedback.get("suggestions") or []
    base = [
        "استخدم طول 12 حرفًا فأكثر.",
        "اخلط أحرفًا كبيرة/صغيرة وأرقامًا ورموزًا.",
        "لا تُعِد استخدام كلمة المرور نفسها في أكثر من موقع."
    ]
    merged, seen = [], set()
    for s in [*suggestions, *base]:
        if s and s not in seen:
            merged.append(s); seen.add(s)
    return {"warning": warning, "suggestions": merged}

def check_pwned_password(pw: str, timeout_sec=5.0):
    if not pw:
        return False, 0
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordChecker/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_sec, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
        for line in body.splitlines():
            part = line.strip().split(":")
            if len(part) == 2 and part[0].upper() == suffix:
                return True, int(part[1])
        return False, 0
    except Exception:
        return False, 0

def analyze_password(pw: str):
    meta = {
        "length": len(pw),
        "has_upper": bool(re.search(r"[A-Z]", pw)),
        "has_lower": bool(re.search(r"[a-z]", pw)),
        "has_digit": bool(re.search(r"\d", pw)),
        "has_symbol": bool(re.search(r"[^A-Za-z0-9]", pw)),
    }

    found, count = check_pwned_password(pw)
    pwned = {"found": bool(found), "count": int(count)}

    crack_ar, method_ar = "غير معروف", "غير محدد"
    if ZXCVBN_AVAILABLE:
        res = zxcvbn(pw)
        score = int(res.get("score", 0))
        crack_map = res.get("crack_times_display", {}) or {}
        crack_en = (crack_map.get("offline_slow_hashing_1e4_per_second")
                    or crack_map.get("online_no_throttling_10_per_second")
                    or "")
        crack_ar = _translate_crack_time(crack_en)
        method_ar = "محاولات مباشرة (بدون قيود)" if "10 per second" in crack_en else "قوة غاشمة/قاموس"
        feedback_ar = _translate_feedback(res.get("feedback", {}) or {})
    else:
        score, crack_ar, feedback_ar = simple_fallback_score(pw)
        method_ar = "تقدير بسيط (بدون ZXCVBN)"

    if found:
        feedback_ar["warning"] = f"⚠️ هذه الكلمة ظهرت في تسريبات {count:,} مرة."
        score = min(score, 1)

    return score, crack_ar, method_ar, feedback_ar, meta, pwned

@app.post("/api/password/score")
def api_password_score():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")

    score, crack, method, feedback, meta, pwned = analyze_password(pw)

    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO password_tests
                (user_id, score, created_at, length, has_upper, has_lower, has_digit, has_symbol, is_pwned, pwn_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request.headers.get("X-User-Id", None),
                score,
                _utcnow(),
                meta["length"], int(meta["has_upper"]), int(meta["has_lower"]),
                int(meta["has_digit"]), int(meta["has_symbol"]),
                int(pwned["found"]), int(pwned["count"])
            ))
    except Exception:
        pass

    base = 5
    if score >= 3:
        base += 5
    _grant_points(base, kind="password", meta={"score": score})

    return jsonify({
        "score": score,
        "crack_time_display": crack,
        "crack_method": method,
        "feedback": feedback,
        "pwned": pwned
    }), 200

# =========================================================
# ================ Security Analysis: URLs ================
# (UNCHANGED logic — included for completeness)
# =========================================================

def analyze_url_local(url: str):
    reasons, score = [], 100
    url = (url or "").strip()

    lower = url.lower()
    if re.match(r'^(javascript|data|file|vbscript):', lower):
        return {
            "verdict": "خطر",
            "score": 0,
            "reasons": ["مخطط رابط غير آمن (javascript/data/file/vbscript)"],
            "hostname": ""
        }

    if not url or not lower.startswith(("http://", "https://")):
        return {"verdict": "خطر", "score": 10, "reasons": ["الرابط لا يبدأ بـ http/https"], "hostname": ""}

    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return {"verdict": "خطر", "score": 10, "reasons": ["صيغة الرابط غير صالحة"], "hostname": ""}

    host = (p.hostname or "").lower()

    if (p.scheme or "").lower() == "http":
        reasons.append("الرابط يستخدم http (بدون تشفير)")
        score -= 40

    dangerous_tlds = (".ru", ".tk", ".cf", ".zip", ".mov", ".click")
    if any(host.endswith(t) for t in dangerous_tlds):
        reasons.append("امتداد نطاق خطير")
        score -= 60

    if "@" in (p.netloc or ""):
        reasons.append("وجود @ قد يخفي النطاق الحقيقي")
        score -= 30

    if host.startswith("xn--"):
        reasons.append("Punycode مشبوه")
        score -= 25

    phishy = ["login", "verify", "update", "bank", "paypal", "gift", "free", "prize", "bonus", "reset"]
    if any(w in lower for w in phishy):
        reasons.append("كلمات تصيّد")
        score -= 25

    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host):
        reasons.append("استخدام عنوان IP بدل نطاق")
        score -= 20

    if len(url) > 180:
        reasons.append("الرابط طويل")
        score -= 10

    verdict = "آمن" if score >= 80 else ("مشبوه" if score >= 55 else "خطر")
    return {
        "verdict": verdict,
        "score": max(0, min(100, score)),
        "reasons": reasons,
        "hostname": host
    }

@app.post("/api/url/check")
def api_url_check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    result = analyze_url_local(url)

    if url:
        result["screenshot"] = f"https://s.wordpress.com/mshots/v1/{url}?w=600"

    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO url_checks (user_id, created_at, url_hash, hostname, verdict, score, reasons)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                request.headers.get("X-User-Id", None),
                _utcnow(),
                hashlib.sha256(url.encode("utf-8")).hexdigest() if url else "",
                result.get("hostname"), result.get("verdict"),
                int(result.get("score")), " | ".join(result.get("reasons", [])),
            ))
    except Exception:
        pass

    _grant_points(3, kind="url", meta={"verdict": result.get("verdict"), "score": result.get("score")})
    return jsonify(result), 200

# =========================================================
# ================ Security Analysis: Emails ==============
# =========================================================

def analyze_email(sender: str, subject: str, body: str):
    reasons, score = [], 100
    phishy_words = ["urgent", "verify", "reset", "password", "bank", "account", "locked",
                    "click here", "update", "suspended", "confirm", "free", "bonus", "lottery"]
    text = f"{subject} {body}".lower()
    if any(w in text for w in phishy_words):
        reasons.append("كلمات تصيّد"); score -= 30
    if sender and "@" in sender:
        domain = sender.split("@")[-1].lower()
        if any(d in domain for d in ["paypa1", "g00gle", "micros0ft"]):
            reasons.append("انتحال نطاق"); score -= 40
        if domain.endswith((".ru", ".tk", ".cf")):
            reasons.append("امتداد خطير"); score -= 30
    if any(ext in body.lower() for ext in [".exe", ".zip", ".scr"]):
        reasons.append("مرفقات مشبوهة"); score -= 40
    verdict = "آمن" if score >= 80 else ("مشبوه" if score >= 55 else "خطر")
    return {"verdict": verdict, "score": max(0, min(100, score)), "reasons": reasons}

@app.post("/api/email/check")
def api_email_check():
    data = request.get_json(silent=True) or {}
    sender = (data.get("sender") or "").strip()
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()

    result = analyze_email(sender, subject, body)
    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO email_checks (user_id, created_at, sender, subject, verdict, score, reasons)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                request.headers.get("X-User-Id", None),
                _utcnow(),
                sender, subject, result["verdict"], int(result["score"]),
                " | ".join(result.get("reasons", []))
            ))
    except Exception:
        pass

    _grant_points(3, kind="email", meta={"verdict": result.get("verdict"), "score": result.get("score")})
    return jsonify(result), 200

# =========================================================
# ====== (NEW) Secure Ingest for Login Attempts (HMAC) ====
# =========================================================

import hmac

SHARED_INGEST_SECRET = "a9c5f4d3d2e14f87a1b6c0c9f0d2e7a5b4c39f7d2e1c4a8f9e3b6c1d0a2f7e9b"

def _make_sig(secret: str, ts: str, body: bytes) -> str:
    return hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()

def _verify_sig(req) -> bool:
    ts = req.headers.get("X-Signature-Timestamp", "")
    sig = req.headers.get("X-Signature", "")
    try:
        t = int(ts)
    except Exception:
        return False
    if abs(int(time.time()) - t) > 300:
        return False
    good = _make_sig(SHARED_INGEST_SECRET, ts, req.get_data() or b"")
    return hmac.compare_digest(good, sig)

@app.post("/api/ingest/login")
def ingest_login_attempt():
    if not _verify_sig(request):
        return jsonify({"ok": False, "error": "bad_signature"}), 401

    data = request.get_json(silent=True) or {}
    success = 1 if bool(data.get("success")) else 0
    ip  = (data.get("ip") or request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown").split(",")[0].strip()
    ua  = data.get("user_agent") or request.headers.get("User-Agent", "-")
    username = (data.get("username") or data.get("username_hash") or "").strip()
    reason = (data.get("reason") or "").strip()
    sim = data.get("pw_similarity")
    try:
        pw_sim = float(sim) if sim is not None else None
    except:
        pw_sim = None

    label = "success" if success else "fail_typo"
    if success == 0:
        with get_conn() as c:
            window = '-10 minutes'
            cur = c.execute("""
                SELECT
                  SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) as fails
                FROM login_attempts
                WHERE created_at >= datetime('now', ?) AND (ip=? OR username=?)
            """, (window, ip, username))
            row = cur.fetchone()
            fails_window = int(row[0] or 0)

        if pw_sim is None or pw_sim < 0.7 or fails_window >= 5:
            label = "fail_bruteforce"

    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO login_attempts (username, ip, user_agent, success, created_at, reason, pw_similarity, risk_label)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (username, ip, ua, success, _utcnow(), reason, pw_sim, label))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    return jsonify({"ok": True, "risk_label": label}), 200

# =========================================================
# ================ Fake Login Monitor (Demo) ==============
# =========================================================

def detect_bruteforce_window(conn, minutes=10, fail_threshold=5, username_filter: str | None = None):
    cur = conn.cursor()

    if username_filter:
        cur.execute("""
            SELECT ip, COUNT(*) AS fails
            FROM login_attempts
            WHERE success=0
              AND created_at >= datetime('now', ?)
              AND (username = ?)
            GROUP BY ip
            HAVING COUNT(*) >= ?
            ORDER BY fails DESC
        """, (f'-{minutes} minutes', username_filter, fail_threshold))
    else:
        cur.execute("""
            SELECT ip, COUNT(*) AS fails
            FROM login_attempts
            WHERE success=0 AND created_at >= datetime('now', ?)
            GROUP BY ip
            HAVING COUNT(*) >= ?
            ORDER BY fails DESC
        """, (f'-{minutes} minutes', fail_threshold))
    ip_alerts = [{"ip": ip, "fails": fails} for (ip, fails) in cur.fetchall()]

    if username_filter:
        cur.execute("""
            SELECT username, COUNT(*) AS fails
            FROM login_attempts
            WHERE success=0
              AND created_at >= datetime('now', ?)
              AND username = ?
            GROUP BY username
            HAVING COUNT(*) >= ?
            ORDER BY fails DESC
        """, (f'-{minutes} minutes', username_filter, fail_threshold))
    else:
        cur.execute("""
            SELECT username, COUNT(*) AS fails
            FROM login_attempts
            WHERE success=0 AND username IS NOT NULL AND username<>'' AND created_at >= datetime('now', ?)
            GROUP BY username
            HAVING COUNT(*) >= ?
            ORDER BY fails DESC
        """, (f'-{minutes} minutes', fail_threshold))
    user_alerts = [{"username": u, "fails": fails} for (u, fails) in cur.fetchall()]

    alerts = []
    for it in ip_alerts:
        alerts.append({
            "type": "ip_bruteforce",
            "message": f"تم رصد {it['fails']} فشل من نفس الـ IP خلال {minutes} دقيقة: {it['ip']}",
            "ip": it["ip"]
        })
    for it in user_alerts:
        alerts.append({
            "type": "user_targeted",
            "message": f"محاولات متكررة على المستخدم {it['username']} ({it['fails']} فشل خلال {minutes} دقيقة).",
            "username": it["username"]
        })
    return alerts

# =========================================================
# 🧩 Proxy Login Endpoint — Converts /api/login → /api/auth/login
# =========================================================
@app.post("/api/login")
def proxy_api_login():
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        pin = (data.get("password") or data.get("pin") or "").strip()

        with get_conn() as conn:
            row = conn.execute(
                "SELECT id, pin_hash, role FROM users WHERE username=?", (username,)
            ).fetchone()

        ok = False
        if row:
            stored_hash = row[1]
            try:
                if check_password_hash(stored_hash, pin):
                    ok = True
            except Exception:
                ok = False

        if not ok:
            with get_conn() as conn:
                conn.execute("""
                    INSERT INTO login_attempts (username, ip, user_agent, success, created_at)
                    VALUES (?, ?, ?, 0, ?)
                """, (username, request.remote_addr or "-", request.headers.get("User-Agent","-"), _utcnow()))
            return jsonify({"status": "fail", "msg": "❌ بيانات الدخول غير صحيحة"}), 401

        uid = int(row[0])
        role = row[2] if len(row) > 2 else "public"
        session["uid"] = uid
        session["username"] = username
        session["role"] = role

        with get_conn() as conn:
            conn.execute("UPDATE users SET last_seen=? WHERE id=?", (_utcnow(), uid))
            conn.execute("""
                INSERT OR IGNORE INTO user_points (user_id, points, level, streak_days, last_daily)
                VALUES (?, ?, ?, ?, ?)
            """, (uid, 0, 1, 0, None))

        return jsonify({"status": "ok", "msg": "✅ دخول ناجح", "user_id": uid, "username": username})
    except Exception as e:
        return jsonify({"status": "fail", "msg": f"⚠️ خطأ داخلي: {e}"}), 500

# =========================================================
# ================ Monitor Page ===========================
# =========================================================
@app.route("/login-monitor")
def login_monitor():
    if not _is_staff():
        return ("الصفحة غير موجودة", 404)

    me = _current_username()
    role = getattr(g, "role", "public")

    username_filter = me if role == "staff" else None

    with get_conn() as conn:
        cur = conn.cursor()
        if username_filter:
            cur.execute("""
                SELECT username, ip, user_agent, success, created_at, risk_label, pw_similarity
                FROM login_attempts
                WHERE username = ?
                ORDER BY created_at DESC
                LIMIT 100;
            """, (username_filter,))
        else:
            cur.execute("""
                SELECT username, ip, user_agent, success, created_at, risk_label, pw_similarity
                FROM login_attempts
                ORDER BY created_at DESC
                LIMIT 100;
            """)

        rows = []
        for r in cur.fetchall():
            success = bool(r[3])
            risk = r[5] or ("success" if success else "fail_typo")
            rows.append({
                "username": r[0] or "",
                "ip": r[1] or "",
                "ua": r[2] or "",
                "success": success,
                "created_at": r[4],
                "risk_label": risk,
                "pw_similarity": (None if r[6] is None else float(r[6])),
            })

        alerts = detect_bruteforce_window(conn, minutes=10, fail_threshold=5, username_filter=username_filter)

    return render_template("monitor.html", attempts=rows, alerts=alerts, scoped=bool(username_filter), me=me, is_admin=_is_admin())

# =========================================================
# ================ Quiz ===================================
# =========================================================

def load_questions():
    path = os.path.join(BASE_DIR, "quiz_questions.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            print("Error loading questions: JSON is not a list")
            return []
        return data
    except Exception as e:
        print("Error loading questions:", e)
        return []

@app.get("/api/quiz/questions")
def api_quiz_questions():
    try:
        count = int(request.args.get("count", 5))
    except Exception:
        count = 5

    questions = load_questions()
    if not questions:
        return jsonify([{
            "id": 1,
            "question": "ملف الأسئلة غير موجود أو تالف.",
            "options": ["—"],
            "answer": 0
        }]), 200

    used_ids = set(session.get("quiz_used_ids", []))
    pool = [q for q in questions if q.get("id") not in used_ids]

    if len(pool) < count:
        used_ids = set()
        pool = questions[:]

    random.shuffle(pool)
    selected = pool[:max(1, min(count, len(pool)))]

    used_ids.update(q.get("id") for q in selected if "id" in q)
    session["quiz_used_ids"] = list(used_ids)

    for q in selected:
        opts = list(q.get("options", []))
        ans_index = int(q.get("answer", 0)) if isinstance(q.get("answer", 0), int) else 0
        if 0 <= ans_index < len(opts):
            correct_text = opts[ans_index]
            random.shuffle(opts)
            q["options"] = opts
            q["answer"] = opts.index(correct_text)
        else:
            q["answer"] = 0

    return jsonify(selected), 200

@app.post("/api/quiz/reset")
def api_quiz_reset():
    session["quiz_used_ids"] = []
    return jsonify({"ok": True}), 200

@app.post("/api/quiz/submit")
def api_quiz_submit():
    data = request.get_json(silent=True) or {}
    score = int(data.get("score", 0))
    total = int(data.get("total", 0))
    answers = data.get("answers", {})  # ✅ من الواجهة الجديدة
    detail = {}

    # 🔹 نحمل ملف الأسئلة مع التصنيفات
    try:
        with open("quiz_questions.json", "r", encoding="utf-8") as f:
            questions = json.load(f)
    except Exception as e:
        print("⚠️ failed to load quiz_questions.json:", e)
        questions = []

    # 🔹 نبني detail يحتوي على: رقم السؤال + هل صح أو خطأ + التصنيف
    for q in questions:
        qid = str(q.get("id"))
        cat = q.get("category", "غير محدد")
        user_ans = answers.get(qid)
        correct_index = q.get("answer")
        is_correct = (user_ans == correct_index)
        detail[qid] = {
            "correct": is_correct,
            "category": cat
        }

    # ✅ نجيب user_id من الجلسة
    user_id = session.get("uid")

    # 🔸 حفظ النتيجة في قاعدة البيانات
    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO quiz_attempts (user_id, score, total, created_at, detail_json)
                VALUES (?, ?, ?, ?, ?)
            """, (
                user_id,
                score, total, _utcnow(),
                json.dumps(detail, ensure_ascii=False)
            ))
    except Exception as e:
        print("⚠️ quiz insert error:", e)

    # 🎁 حساب النقاط والمكافأة
    bonus = 0
    try:
        if total > 0:
            ratio = max(0.0, min(1.0, float(score) / float(total)))
            bonus = int(round(ratio * 50))
    except Exception:
        pass

    _grant_points(bonus, kind="quiz", meta={"score": score, "total": total})

    return jsonify({"ok": True}), 200


def get_user_role(user_id: int) -> str:
    with get_conn() as conn:
        r = conn.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        return (r[0] if r else "public") or "public"

def is_staff(user_id: int) -> bool:
    return get_user_role(user_id) in ("staff", "admin")

# ================ Admin: Users & Controls =================
def _admin_allowed():
    return request.args.get("pw", "") == ADMIN_PASSWORD or request.form.get("pw", "") == ADMIN_PASSWORD

@app.route("/admin")
def admin_panel():
    if not _admin_allowed():
        return "🚫 غير مصرح بالدخول", 403
    pw = request.args.get("pw", "")
    return f"""
<!doctype html><html><head><meta charset="utf-8"><title>لوحة الإدارة</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;direction:rtl;padding:18px;background:#f8fbff}}
h1{{margin:0 0 16px}}
form, .card{{background:#fff;border:1px solid #e6eef6;border-radius:12px;padding:12px;margin:10px 0}}
label{{display:block;font-weight:800;margin:6px 0 4px}}
input,select{{padding:8px 10px;border:1px solid #dfe7f2;border-radius:8px;width:100%;box-sizing:border-box}}
.row{{display:flex;gap:10px;align-items:center}}
.btn{{background:#0c8f79;border:none;color:#fff;font-weight:900;border-radius:10px;padding:9px 14px;cursor:pointer;text-decoration:none;display:inline-block}}
hr{{border:none;border-top:1px solid #eee;margin:12px 0}}
.small{{color:#6b7d95}}
</style></head><body>
<h1>لوحة الإدارة</h1>

<div style="margin:10px 0">
  <a href="/" class="btn" style="background:#2563eb;text-decoration:none;">🏠 العودة إلى الصفحة الرئيسية</a>
</div>

<div class="card">
  <h3>عرض جميع المستخدمين</h3>
  <form method="get" action="/admin/users">
    <label>كلمة سر الإدارة</label>
    <input name="pw" placeholder="أدخلي كلمة السر" required>
    <div class="row" style="justify-content:flex-end">
      <button class="btn">عرض</button>
    </div>
  </form>
  <hr>
  <a href="/admin/quiz-report?pw={pw}" class="btn" style="background:#1e5aa6;">📊 تقرير الكويز الأمني</a>
</div>

<div class="card">
  <h3>تعديل بيانات مستخدم</h3>
  <form method="post" action="/admin/user/update">
    <label>كلمة سر الإدارة</label>
    <input name="pw" required>
    <label>ID المستخدم</label>
    <input name="user_id" type="number" required>

    <div class="row">
      <div style="flex:1"><label>النقاط</label><input name="points" type="number" placeholder="اتركيها فاضية بدون تغيير"></div>
      <div style="flex:1"><label>المستوى</label><input name="level" type="number" placeholder="اتركيها فاضية بدون تغيير"></div>
      <div style="flex:1"><label>سلسلة الأيام</label><input name="streak" type="number" placeholder="اتركيها فاضية بدون تغيير"></div>
    </div>

    <div class="row" style="margin-top:8px">
      <div style="flex:1">
        <label>طبيعة المستخدم</label>
        <select name="role">
          <option value="">— بدون تغيير —</option>
          <option value="public">طبيعي</option>
          <option value="staff">موظف</option>
          <option value="admin">مدير</option>
        </select>
      </div>
    </div>

    <div class="row" style="justify-content:flex-end"><button class="btn">تطبيق التغييرات</button></div>
  </form>
</div>

<div class="card">
  <h3>حذف / استرجاع مستخدم</h3>
  <form method="post" action="/admin/user/soft_delete">
    <label>كلمة سر الإدارة</label><input name="pw" required>
    <label>ID المستخدم</label><input name="user_id" type="number" required>
    <div class="row" style="justify-content:flex-end"><button class="btn" style="background:#d12e3a">حذف ناعم (تعطيل)</button></div>
  </form>
  <hr>
  <form method="post" action="/admin/user/restore">
    <label>كلمة سر الإدارة</label><input name="pw" required>
    <label>ID المستخدم</label><input name="user_id" type="number" required>
    <div class="row" style="justify-content:flex-end"><button class="btn" style="background:#1e5aa6">استرجاع</button></div>
  </form>
  <hr>
  <form method="post" action="/admin/user/hard_delete">
    <label>كلمة سر الإدارة</label><input name="pw" required>
    <label>ID المستخدم</label><input name="user_id" type="number" required>
    <div class="row" style="justify-content:flex-end"><button class="btn" style="background:#000">حذف نهائي (لا يمكن التراجع)</button></div>
  </form>
</div>

<div class="small">ملاحظة: الحذف الناعم يملأ عمود deleted_at في users فقط. الحذف النهائي يمسح المستخدم من كل الجداول المرتبطة.</div>
</body></html>
    """

@app.route("/admin/users")
def list_users():
    if not _admin_allowed():
        return "🚫 غير مصرح بالدخول", 403

    show_deleted = request.args.get("show_deleted", "0") == "1"

    with get_conn() as conn:
        cur = conn.execute(f"""
            SELECT u.id, u.username, u.role, u.created_at, u.last_seen, u.deleted_at,
                   p.points, p.level, p.streak_days
            FROM users u
            LEFT JOIN user_points p ON u.id = p.user_id
            {"WHERE u.deleted_at IS NULL" if not show_deleted else ""}
            ORDER BY u.created_at DESC
        """)
        rows = cur.fetchall()

    def cell(v):
        return v if (v is not None and v != "") else "—"

    html = [
        "<!doctype html><html><head><meta charset='utf-8'><title>قائمة المستخدمين</title>",
        "<style>body{font-family:Arial,Helvetica,sans-serif;direction:rtl;padding:18px;background:#f8fbff}",
        "table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e6eef6;border-radius:12px;overflow:hidden}",
        "th,td{border-bottom:1px solid #eef3f8;padding:10px 8px;text-align:center}th{background:#f4fbff;font-weight:900}",
        ".top{display:flex;gap:10px;align-items:center;margin-bottom:10px}",
        ".chip{display:inline-block;padding:4px 10px;border:1px solid #dfe7f2;border-radius:999px;background:#fff}",
        "a.btn{display:inline-block;background:#0c8f79;color:#fff;text-decoration:none;padding:8px 12px;border-radius:10px;font-weight:900}",
        ".role-admin{color:#eab308;font-weight:700}.role-staff{color:#22c55e;font-weight:700}.role-public{color:#94a3b8;font-weight:700}",
        "</style></head><body>",
        "<div class='top'>",
        f"<a class='btn' href='/admin?pw={request.args.get('pw','')}'>↩ رجوع للوحة</a>",
        f"<span class='chip'>عرض: {'الكل' if show_deleted else 'النشط فقط'}</span>",
        f"<a class='btn' href='/admin/users?pw={request.args.get('pw','')}&show_deleted={'0' if show_deleted else '1'}'>بدّل العرض</a>",
        "</div>",
        "<table>",
        "<tr><th>ID</th><th>اسم المستخدم</th><th>الدور</th><th>تاريخ الإنشاء</th><th>آخر ظهور</th><th>محذوف؟</th><th>نقاط</th><th>مستوى</th><th>ستريك</th></tr>"
    ]
    for r in rows:
        uid, uname, role, created, last_seen, deleted_at, points, level, streak = r
        role_class = f"role-{role}" if role in ("admin", "staff", "public") else ""
        html.append(
            f"<tr><td>{uid}</td>"
            f"<td>{cell(uname)}</td>"
            f"<td class='{role_class}'>{cell(role)}</td>"
            f"<td>{cell(created)}</td>"
            f"<td>{cell(last_seen)}</td>"
            f"<td>{'نعم' if deleted_at else 'لا'}</td>"
            f"<td>{points or 0}</td>"
            f"<td>{level or 1}</td>"
            f"<td>{streak or 0}</td></tr>"
        )
    html.append("</table></body></html>")
    return "".join(html)


@app.post("/admin/user/soft_delete")
def admin_soft_delete():
    if not _admin_allowed():
        return "🚫 غير مصرح بالدخول", 403
    try:
        user_id = int(request.form.get("user_id", "0"))
    except Exception:
        return "ID غير صالح", 400
    with get_conn() as conn:
        conn.execute("UPDATE users SET deleted_at=? WHERE id=?", (_utcnow(), user_id))
    return "تم الحذف (ناعم)."

@app.post("/admin/user/restore")
def admin_restore():
    if not _admin_allowed():
        return "🚫 غير مصرح بالدخول", 403
    try:
        user_id = int(request.form.get("user_id", "0"))
    except Exception:
        return "ID غير صالح", 400
    with get_conn() as conn:
        conn.execute("UPDATE users SET deleted_at=NULL WHERE id=?", (user_id,))
    return "تم الاسترجاع."

@app.post("/admin/user/hard_delete")
def admin_hard_delete():
    if not _admin_allowed():
        return "🚫 غير مصرح بالدخول", 403
    try:
        user_id = int(request.form.get("user_id", "0"))
    except Exception:
        return "ID غير صالح", 400
    with get_conn() as conn:
        conn.execute("DELETE FROM point_events WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM user_points WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM quiz_attempts WHERE user_id=?", (str(user_id),))
        conn.execute("DELETE FROM email_checks WHERE user_id=?", (str(user_id),))
        conn.execute("DELETE FROM url_checks   WHERE user_id=?", (str(user_id),))
        conn.execute("DELETE FROM password_tests WHERE user_id=?", (str(user_id),))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    return "تم الحذف النهائي."

@app.post("/admin/user/update")
def admin_update_user():
    if not _admin_allowed():
        return "🚫 غير مصرح بالدخول", 403
    try:
        user_id = int(request.form.get("user_id", "0"))
    except Exception:
        return "ID غير صالح", 400

    points = request.form.get("points", "").strip()
    level  = request.form.get("level", "").strip()
    streak = request.form.get("streak", "").strip()
    role   = (request.form.get("role", "") or "").strip()

    allowed_roles = {"public", "staff", "admin"}
    set_role = role if role in allowed_roles else None

    with get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO user_points (user_id, points, level, streak_days, last_daily) VALUES (?,?,?,?,?)",
                     (user_id, 0, 1, 0, None))
        cur = conn.execute("SELECT points, level, streak_days, last_daily FROM user_points WHERE user_id=?", (user_id,))
        row = cur.fetchone()
        if not row:
            return "المستخدم غير موجود", 404
        cur_points, cur_level, cur_streak, last_daily = row

        new_points = cur_points if points=="" else max(0, int(points))
        new_level  = cur_level  if level==""  else max(1, int(level))
        new_streak = cur_streak if streak=="" else max(0, int(streak))

        conn.execute("""
            UPDATE user_points SET points=?, level=?, streak_days=? WHERE user_id=?
        """, (new_points, new_level, new_streak, user_id))

        if set_role is not None:
            conn.execute("UPDATE users SET role=? WHERE id=?", (set_role, user_id))

    return "تم التعديل."

# =========================================================
# ================ Admin: Quiz Report =====================
# =========================================================

@app.route("/admin/quiz-report")
def admin_quiz_report():
    if not _admin_allowed():
        return "🚫 غير مصرح بالدخول", 403

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT
              u.username,
              qa.score,
              qa.total,
              qa.created_at,
              qa.detail_json
            FROM quiz_attempts qa
            LEFT JOIN users u ON u.id = qa.user_id
            WHERE qa.total > 0
              AND u.role = 'staff'
            ORDER BY qa.created_at DESC
        """)
        rows = cur.fetchall()

    results = {}
    for username, score, total, created, detail_json in rows:
        if not username:
            continue

        percent = round((score / total) * 100, 1)
        if username not in results:
            results[username] = {
                "scores": [],
                "dates": [],
                "fails": {}
            }

        results[username]["scores"].append(percent)
        results[username]["dates"].append(created)

        # ✅ تحليل الفئات حسب detail_json
        try:
            detail = json.loads(detail_json or "{}")
            for qid, qdata in detail.items():
                if not qdata.get("correct"):
                    cat = qdata.get("category", "غير محدد")
                    results[username]["fails"][cat] = results[username]["fails"].get(cat, 0) + 1
        except Exception as e:
            print("⚠️ تحليل detail_json:", e)
            continue

    table = []
    for user, data in results.items():
        avg = round(sum(data["scores"]) / len(data["scores"]), 1)
        level = (
            "ممتاز" if avg >= 85 else
            "جيد جدًا" if avg >= 70 else
            "يحتاج توعية" if avg >= 50 else
            "ضعيف"
        )

        # 🔍 نحدد أكثر نوع أخطأ فيه
        weak_cat = "—"
        if data["fails"]:
            weak_cat = max(data["fails"], key=data["fails"].get)

        table.append({
            "username": user,
            "avg": avg,
            "attempts": len(data["scores"]),
            "level": level,
            "weak_cat": weak_cat
        })

    table.sort(key=lambda x: x["avg"])

    return render_template("quiz_report.html", table=table)

# =========================================================
# ================ Pages ==================================
# =========================================================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/password")
def password_page():
    return render_template("password.html")

@app.route("/url")
def url_page():
    return render_template("url.html")

@app.route("/email")
def email_page():
    return render_template("email.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/quiz")
def quiz_page():
    return render_template("quiz.html")

@app.route("/profile")
def profile_page():
    uid = session.get("uid")
    username = session.get("username")
    if not uid or not username:
        return redirect(url_for("login_page"))

    with get_conn() as conn:
        row = conn.execute("""
            SELECT points, level, streak_days, last_daily
            FROM user_points WHERE user_id=?
        """, (uid,)).fetchone()

    if not row:
        return redirect(url_for("index"))

    points, level, streak, last_daily = row
    return render_template(
        "profile.html",
        username=username,
        points=points,
        level=level,
        streak=streak,
        last_daily=last_daily
    )

@app.get("/api/auth/check")
def api_auth_check():
    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"ok": False, "error": "أدخلي اسمًا"}), 400
    if not re.match(r"^[A-Za-z0-9_\.]{3,16}$", username):
        return jsonify({"ok": False, "error": "٣–١٦ حرفًا/رقمًا/نقطة/شرطة سفلية فقط"}), 200
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    return jsonify({"ok": True, "available": (row is None)})

@app.post("/api/claim-daily")
def api_claim_daily_v2():
    uid = session.get("uid")
    if not uid:
        return jsonify({"ok": False, "error": "لم تسجلي الدخول"}), 403

    now = datetime.utcnow()
    with get_conn() as conn:
        row = conn.execute("SELECT points, streak_days, last_daily FROM user_points WHERE user_id=?", (uid,)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "بيانات المستخدم غير موجودة"})
        points, streak, last_daily = row

        if last_daily and last_daily.split("T")[0] == now.strftime("%Y-%m-%d"):
            return jsonify({"ok": False, "error": "لقد تم استلام مكافأة اليوم مسبقًا!"})

        streak = streak + 1
        points = points + 10
        conn.execute("""
            UPDATE user_points SET points=?, streak_days=?, last_daily=?
            WHERE user_id=?
        """, (points, streak, now.strftime("%Y-%m-%dT%H:%M:%S"), uid))

    return jsonify({"ok": True, "added": 10, "points": points, "streak": streak})

# =========================================================
# ================ Boot & DB Reset ========================
# =========================================================

def upgrade_existing_db():
    """
    Attempt to upgrade schema if needed (kept for safety/backwards compat).
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(users);")
        user_cols = [r[1] for r in cur.fetchall()]

        if "pin_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN pin_hash TEXT")
        if "role" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'public'")
        if "deleted_at" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN deleted_at TEXT")

        cur.execute("PRAGMA table_info(user_points);")
        cols = [r[1] for r in cur.fetchall()]
        if not cols:
            init_core_tables()

        cur.execute("PRAGMA table_info(login_attempts);")
        cols = [r[1] for r in cur.fetchall()]
        if "reason" not in cols:
            try: conn.execute("ALTER TABLE login_attempts ADD COLUMN reason TEXT")
            except: pass
        if "pw_similarity" not in cols:
            try: conn.execute("ALTER TABLE login_attempts ADD COLUMN pw_similarity REAL")
            except: pass
        if "risk_label" not in cols:
            try: conn.execute("ALTER TABLE login_attempts ADD COLUMN risk_label TEXT")
            except: pass

        init_core_tables()
        conn.execute("UPDATE users SET role='public' WHERE role IS NULL OR role=''")
        conn.commit()
 
def init_all():
    init_core_tables()
    init_login_monitoring()
    init_users_and_gamify()

if __name__ == "__main__":
    # حذف قاعدة البيانات القديمة إذا طُلب ذلك — لإعادة ضبط كاملة كما طلبتِ
    if RESET_DB_ON_START and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print("🧹 قاعدة البيانات القديمة تم حذفها — بدء قاعدة جديدة.")
        except Exception as e:
            print("خطأ أثناء حذف قاعدة البيانات القديمة:", e)

    # تهيئة الجداول
    init_all()
    # تشغيل الخادم
    app.run(host="0.0.0.0", port=5000, debug=True)
