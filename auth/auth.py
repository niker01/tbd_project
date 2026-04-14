import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from database.db import DB_NAME, hash_password


def is_password_used_recently(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM password_history WHERE username=? ORDER BY set_date DESC LIMIT 3", (username,))
    for old_hash, old_salt in cursor.fetchall():
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), old_salt.encode(), 100000).hex()
        if new_hash == old_hash:
            conn.close()
            return True
    conn.close()
    return False


# ------------------- ВСТАНОВЛЕННЯ ПАРОЛЯ -------------------

def set_password(username, password, password_type, expiry_days=30):
    if is_password_used_recently(username, password):
        return False
    salt, pwd_hash = hash_password(password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Insert into history
    cursor.execute("INSERT INTO password_history (username, password_hash, salt) VALUES (?, ?, ?)", (username, pwd_hash, salt))
    # Delete old
    cursor.execute("DELETE FROM password_history WHERE id IN (SELECT id FROM password_history WHERE username=? ORDER BY set_date DESC LIMIT -1 OFFSET 3)", (username,))
    # Update user
    cursor.execute("UPDATE users SET password_hash=?, salt=?, password_set_date=?, password_expiry_days=?, password_type=? WHERE username=?", (pwd_hash, salt, datetime.now().isoformat(), expiry_days, password_type, username))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


# ------------------- ОТРИМАННЯ ТИПУ ПАРОЛЯ -------------------

def get_password_type(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT password_type FROM users WHERE username=?
    """, (username,))

    result = cursor.fetchone()

    conn.close()

    return result[0] if result else None


# ------------------- ПЕРЕВІРКА СКЛАДНОСТІ -------------------

def check_complex_password(password):
    if len(password) < 8:
        return False

    sets = [0, 0, 0, 0]

    for c in password:
        if c.islower():
            sets[0] = 1
        elif c.isupper():
            sets[1] = 1
        elif c.isdigit():
            sets[2] = 1
        else:
            sets[3] = 1

    return sum(sets) >= 3


# ------------------- АВТЕНТИФІКАЦІЯ -------------------

def authenticate(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt, password_set_date, password_expiry_days, blocked_until FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    pwd_hash, salt, set_date, expiry_days, blocked_until = row
    now = datetime.now()
    if blocked_until and datetime.fromisoformat(blocked_until) > now:
        conn.close()
        return None  # blocked
    if pwd_hash:
        input_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        if input_hash == pwd_hash:
            # check expiry
            if set_date:
                set_dt = datetime.fromisoformat(set_date)
                if now > set_dt + timedelta(days=expiry_days):
                    conn.close()
                    return None  # expired
            # reset failed attempts
            cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
            conn.commit()
            conn.close()
            return (username,)  # or whatever
        else:
            # failed
            cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_time=? WHERE username=?", (now.isoformat(), username))
            # check if block
            cursor.execute("SELECT failed_attempts FROM users WHERE username=?", (username,))
            attempts = cursor.fetchone()[0]
            if attempts >= 5:  # 5 attempts
                block_until = now + timedelta(minutes=15)
                cursor.execute("UPDATE users SET blocked_until=? WHERE username=?", (block_until.isoformat(), username))
            conn.commit()
            conn.close()
            return None
    conn.close()
    return None


# ------------------- ДОДАТКОВО -------------------

def user_exists(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    conn.close()

    return result is not None