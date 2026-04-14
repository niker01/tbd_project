import sqlite3
import os
import sys
import datetime
import hashlib
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
DB_NAME = os.path.join(BASE_DIR, "Data", "users.db")


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt, hash_obj.hex()


# ---------------- ІНІЦІАЛІЗАЦІЯ ----------------

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "Data"), exist_ok=True)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # --- Користувачі ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        password_type TEXT,
        access_level TEXT DEFAULT 'не таємно'
    )
    """)

    # Password history
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password_hash TEXT,
        salt TEXT,
        set_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Add new columns to users
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN salt TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN password_set_date DATETIME")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN password_expiry_days INTEGER DEFAULT 30")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN last_failed_time DATETIME")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN blocked_until DATETIME")
    except sqlite3.OperationalError:
        pass

    # --- Ресурси ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT UNIQUE,
        confidentiality_level TEXT DEFAULT 'не таємно'
    )
    """)

    # --- DAC ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS discretionary_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        filename TEXT,
        can_read INTEGER DEFAULT 0,
        can_write INTEGER DEFAULT 0,
        can_save INTEGER DEFAULT 0,
        can_execute INTEGER DEFAULT 0,
        time_from INTEGER,
        time_to INTEGER,
        ip TEXT,
        UNIQUE(username, filename)
    )
    """)

    # --- Налаштування ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        access_model TEXT
    )
    """)
    cursor.execute("INSERT OR IGNORE INTO settings (id, access_model) VALUES (1, 'MANDATORY')")

    # --- RBAC ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT UNIQUE
    )
    """)

    # ✅ автостворення ролей
    default_roles = ["Reader", "Editor", "Admin"]
    for role in default_roles:
        cursor.execute(
            "INSERT OR IGNORE INTO roles (role_name) VALUES (?)",
            (role,)
        )

    # ---------------- RBAC ----------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS role_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_id INTEGER,
        filename TEXT,
        can_read INTEGER DEFAULT 0,
        can_write INTEGER DEFAULT 0,
        can_save INTEGER DEFAULT 0,
        can_execute INTEGER DEFAULT 0,
        time_from INTEGER,
        time_to INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(id),
        UNIQUE(role_id, filename)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        role_id INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(id)
    )
    """)

    # --- Behavioral Biometrics ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS behavioral_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        keystroke_features TEXT
    )
    """)

    # --- Login Attempts with Biometrics ---
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        keystroke_features TEXT,
        biometric_status TEXT,
        success INTEGER
    )
    """)

    # --- Дефолтні користувачі ---
    default_users = [
        ("Soltys_1", "не таємно"),
        ("Soltys_2", "таємно"),
        ("Soltys_3", "цілком таємно"),
        ("Soltys_4", "таємно"),
        ("Soltys_5", "не таємно"),
    ]
    for username, level in default_users:
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, access_level) VALUES (?, ?)",
            (username, level)
        )

    # --- Дефолтні ресурси ---
    default_resources = [
        ("soltys1.txt", "не таємно"),
        ("soltys2.txt", "таємно"),
        ("soltys3.txt", "цілком таємно"),
        ("soltysimage.png", "таємно"),
        ("soltys_program.exe", "цілком таємно")
    ]
    for filename, level in default_resources:
        cursor.execute(
            "INSERT OR IGNORE INTO resources (filename, confidentiality_level) VALUES (?, ?)",
            (filename, level)
        )

    default_role_permissions = [
        # Reader: тільки читання
        ("Reader", "soltys1.txt", 1, 0, 0, 0),
        ("Reader", "soltys2.txt", 1, 0, 0, 0),
        ("Reader", "soltys3.txt", 1, 0, 0, 0),
        ("Reader", "soltysimage.png", 1, 0, 0, 0),
        ("Reader", "soltys_program.exe", 1, 0, 0, 0),

        # Editor: читання + запис + збереження
        ("Editor", "soltys1.txt", 1, 1, 1, 0),
        ("Editor", "soltys2.txt", 1, 1, 1, 0),
        ("Editor", "soltys3.txt", 1, 1, 1, 0),
        ("Editor", "soltysimage.png", 1, 1, 1, 0),
        ("Editor", "soltys_program.exe", 1, 1, 1, 0),

        # Admin: всі права
        ("Admin", "soltys1.txt", 1, 1, 1, 1),
        ("Admin", "soltys2.txt", 1, 1, 1, 1),
        ("Admin", "soltys3.txt", 1, 1, 1, 1),
        ("Admin", "soltysimage.png", 1, 1, 1, 1),
        ("Admin", "soltys_program.exe", 1, 1, 1, 1),
    ]

    # Вставка дефолтних прав
    cursor.execute("SELECT id, role_name FROM roles")
    roles = {r[1]: r[0] for r in cursor.fetchall()}

    for role_name, filename, r, w, s, x in default_role_permissions:
        role_id = roles.get(role_name)
        if role_id:
            cursor.execute("""
            INSERT OR IGNORE INTO role_permissions
            (role_id, filename, can_read, can_write, can_save, can_execute)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (role_id, filename, r, w, s, x))

    conn.commit()
    conn.close()


# ---------------- КОРИСТУВАЧІ ----------------

def view_users():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, CASE WHEN password_hash IS NOT NULL THEN 'задано' ELSE '<не задано>' END as password, password_type, access_level FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_user_biometric_stats(username):
    """Отримати біометричну статистику користувача з логів"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Профіль
    cursor.execute("SELECT keystroke_features FROM behavioral_profiles WHERE username = ?", (username,))
    profile_row = cursor.fetchone()
    profile = profile_row[0] if profile_row else None
    
    # Останні 2 спроби входу
    cursor.execute("""
    SELECT login_time, keystroke_features, biometric_status, success
    FROM login_attempts
    WHERE username = ?
    ORDER BY login_time DESC
    LIMIT 2
    """, (username,))
    
    attempts = cursor.fetchall()
    conn.close()
    
    return {
        "profile": profile,
        "attempts": attempts
    }


def add_user(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username) VALUES (?)", (username,))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def set_access_level(username, level):
    allowed_levels = ["не таємно", "таємно", "цілком таємно"]
    if level not in allowed_levels:
        return 0

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET access_level=? WHERE username=?", (level, username))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected


# ---------------- РЕСУРСИ ----------------

def view_resources():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, confidentiality_level FROM resources")
    rows = cursor.fetchall()
    conn.close()
    return rows


def set_confidentiality(filename, level):
    allowed_levels = ["не таємно", "таємно", "цілком таємно"]
    if level not in allowed_levels:
        return 0

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE resources SET confidentiality_level=? WHERE filename=?", (level, filename))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected


# ---------------- DAC ----------------

def set_dac_right(username, filename, r, w, s, x, t_from=None, t_to=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO discretionary_access
    (username, filename, can_read, can_write, can_save, can_execute, time_from, time_to)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(username, filename) DO UPDATE SET
        can_read=excluded.can_read,
        can_write=excluded.can_write,
        can_save=excluded.can_save,
        can_execute=excluded.can_execute,
        time_from=excluded.time_from,
        time_to=excluded.time_to
    """, (username, filename, r, w, s, x, t_from, t_to))

    conn.commit()
    conn.close()


def view_dac():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT username, filename, can_read, can_write, can_save, can_execute
    FROM discretionary_access
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


# ---------------- НАЛАШТУВАННЯ ----------------

def set_access_model(model):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET access_model=? WHERE id=1", (model,))
    conn.commit()
    conn.close()


def get_access_model():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT access_model FROM settings WHERE id=1")
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else "MANDATORY"


# ---------------- RBAC ----------------

def add_role(role_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO roles (role_name) VALUES (?)", (role_name,))
    conn.commit()
    conn.close()


def set_role(username, role_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # перевірка користувача
    cursor.execute("SELECT 1 FROM users WHERE username=?", (username,))
    if not cursor.fetchone():
        conn.close()
        return False

    # перевірка ролі
    cursor.execute("SELECT id FROM roles WHERE role_name=?", (role_name,))
    role = cursor.fetchone()
    if not role:
        conn.close()
        return False

    role_id = role[0]

    # чи вже є роль
    cursor.execute("SELECT id FROM user_roles WHERE username=?", (username,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute(
            "UPDATE user_roles SET role_id=? WHERE username=?",
            (role_id, username)
        )
    else:
        cursor.execute(
            "INSERT INTO user_roles (username, role_id) VALUES (?, ?)",
            (username, role_id)
        )

    conn.commit()
    conn.close()
    return True


def get_user_roles(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT r.role_name FROM roles r
    JOIN user_roles ur ON r.id = ur.role_id
    WHERE ur.username=?
    """, (username,))
    roles = [r[0] for r in cursor.fetchall()]
    conn.close()
    return roles


def check_rbac_access(username, filename, action):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    roles = get_user_roles(username)
    hour = datetime.datetime.now().hour

    for role in roles:
        cursor.execute("""
        SELECT can_read, can_write, can_save, can_execute, time_from, time_to
        FROM role_permissions rp
        JOIN roles r ON rp.role_id = r.id
        WHERE r.role_name=? AND filename=?
        """, (role, filename))

        row = cursor.fetchone()
        if row:
            r, w, s, x, t_from, t_to = row

            # --- перевірка часу ---
            if t_from is not None and t_to is not None:
                if t_from <= t_to and not (t_from <= hour <= t_to):
                    continue
                if t_from > t_to and not (hour >= t_from or hour <= t_to):
                    continue

            allowed = {"read": r, "write": w, "save": s, "execute": x}.get(action, 0)
            if allowed:
                conn.close()
                return True

    conn.close()
    return False

def get_user_password(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username=?",
        (username,)
    )

    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]  # сам пароль
    return None


# ---- ЛОГУВАННЯ СПРОБ ВХОДУ ----

def record_login_attempt(username, keystroke_features, biometric_status, success):
    """Запис спроби входу з біометричними даними"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    INSERT INTO login_attempts (username, keystroke_features, biometric_status, success)
    VALUES (?, ?, ?, ?)
    """, (username, keystroke_features, biometric_status, success))
    
    conn.commit()
    conn.close()


def get_login_attempts(username, limit=10):
    """Отримати останні спроби входу користувача"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT id, login_time, keystroke_features, biometric_status, success
    FROM login_attempts
    WHERE username = ?
    ORDER BY login_time DESC
    LIMIT ?
    """, (username, limit))
    
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_last_successful_login(username):
    """Отримати останню успішну спробу входу"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT keystroke_features, login_time
    FROM login_attempts
    WHERE username = ? AND success = 1
    ORDER BY login_time DESC
    LIMIT 1
    """, (username,))
    
    row = cursor.fetchone()
    conn.close()
    return row
