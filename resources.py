import os
import sys
import sqlite3
import datetime
from database.db import DB_NAME, get_access_model, check_rbac_access, get_user_roles

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
DATA_DIR = os.path.join(BASE_DIR, "Data")


def get_resource_path(filename):
    return os.path.join(DATA_DIR, filename)


# --- MANDATORY ---
def can_access(user_level, resource_level):
    levels = {"не таємно": 1, "таємно": 2, "цілком таємно": 3}
    return levels.get(user_level, 0) >= levels.get(resource_level, 0)

def is_within_time(hour, t_from, t_to):
    """
    Перевірка, чи знаходиться поточна година у дозволеному проміжку.
    Працює і коли t_from > t_to (перетин через північ).
    """
    if t_from is None or t_to is None:
        return True  # без обмежень
    if t_from <= t_to:
        return t_from <= hour <= t_to
    else:
        return hour >= t_from or hour <= t_to

# --- DAC ---
def can_access_dac(username, filename, action):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT can_read, can_write, can_save, can_execute, time_from, time_to
        FROM discretionary_access
        WHERE username=? AND filename=?
    """, (username, filename))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    r, w, s, x, t_from, t_to = row
    hour = datetime.datetime.now().hour

    if not is_within_time(hour, t_from, t_to):
        return False

    return {"read": r == 1, "write": w == 1, "save": s == 1, "execute": x == 1}.get(action, False)

# --- RBAC ---
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

            if not is_within_time(hour, t_from, t_to):
                continue

            allowed = {"read": r, "write": w, "save": s, "execute": x}.get(action, 0)
            if allowed:
                conn.close()
                return True

    conn.close()
    return False

# --- Головна перевірка доступу ---
def can_access_full(username, user_level, resource_level, filename, action):
    model = get_access_model()

    if model == "MANDATORY":
        return can_access(user_level, resource_level)
    elif model == "DAC":
        return can_access_dac(username, filename, action)
    elif model == "RBAC":
        return check_rbac_access(username, filename, action)
    return False