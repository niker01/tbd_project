import sqlite3
import json
import numpy as np
from database.db import init_db, view_users, view_resources, view_dac, get_user_roles, DB_NAME, get_user_biometric_stats

# Ініціалізація
init_db()

conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

# ---------------- КОРИСТУВАЧІ ----------------
users = view_users()
print("Користувачі у базі:")

for u in users:
    username, password, ptype, access = u

    pwd = password if password else "<не задано>"
    ptype = ptype if ptype else "<не задано>"

    # Get password hash
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    hash_row = cursor.fetchone()
    hash_pwd = hash_row[0] if hash_row and hash_row[0] else "<не задано>"

    roles = get_user_roles(username)
    role_str = ", ".join(roles) if roles else "<немає ролі>"

    # Get password expiry info
    cursor.execute("SELECT password_set_date, password_expiry_days, blocked_until FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if row:
        set_date, expiry_days, blocked_until = row
        if set_date:
            from datetime import datetime, timedelta
            set_dt = datetime.fromisoformat(set_date)
            expiry_dt = set_dt + timedelta(days=expiry_days)
            expiry_str = expiry_dt.strftime("%Y-%m-%d %H:%M:%S")
            status = "активний"
            if blocked_until and datetime.fromisoformat(blocked_until) > datetime.now():
                status = "заблокований"
        else:
            expiry_str = "<не встановлено>"
            status = "активний"
    else:
        expiry_str = "<не встановлено>"
        status = "активний"

    print(f"{username} | Пароль: {pwd} | Хеш пароля: {hash_pwd} | Тип: {ptype} | Рівень доступу: {access} | Ролі: {role_str} | Термін дії пароля до: {expiry_str} | Статус: {status}")
    
    # ========== БІОМЕТРІЯ ==========
    stats = get_user_biometric_stats(username)
    if stats["profile"]:
        profile = json.loads(stats["profile"])
        
        # Форматування параметрів профіля з назвами
        dwell_mean = round(profile[0], 4)
        dwell_std = round(profile[1], 4)
        dwell_min = round(profile[2], 4)
        dwell_max = round(profile[3], 4)
        flight_mean = round(profile[4], 4) if len(profile) > 4 else 0
        flight_std = round(profile[5], 4) if len(profile) > 5 else 0
        flight_min = round(profile[6], 4) if len(profile) > 6 else 0
        flight_max = round(profile[7], 4) if len(profile) > 7 else 0
        
        print(f"  📊 Профіль поведінки:")
        print(f"     📍 Утримання клавіш (Dwell Time) ms: mean={dwell_mean}, std={dwell_std}, min={dwell_min}, max={dwell_max}")
        print(f"     📍 Час між клавішами (Flight Time) ms: mean={flight_mean}, std={flight_std}, min={flight_min}, max={flight_max}")
        
        if stats["attempts"]:
            print(f"     Останні спроби входу:")
            for attempt in stats["attempts"]:
                login_time, features_str, biometric_status, success = attempt
                features = json.loads(features_str)
                
                # Форматування спроб з назвами параметрів
                f_dwell_mean = round(features[0], 4)
                f_dwell_std = round(features[1], 4)
                f_dwell_min = round(features[2], 4)
                f_dwell_max = round(features[3], 4)
                f_flight_mean = round(features[4], 4) if len(features) > 4 else 0
                f_flight_std = round(features[5], 4) if len(features) > 5 else 0
                f_flight_min = round(features[6], 4) if len(features) > 6 else 0
                f_flight_max = round(features[7], 4) if len(features) > 7 else 0
                
                # Обчислення різниці у відсотках
                prof_arr = np.array(profile)
                feat_arr = np.array(features)
                diff = np.abs(feat_arr - prof_arr)
                
                dwell_diff = diff[:4] / (np.abs(prof_arr[:4]) + 1e-10) * 100
                flight_diff = diff[4:] / (np.abs(prof_arr[4:]) + 1e-10) * 100
                
                max_dwell_pct = round(np.max(dwell_diff) if len(dwell_diff) > 0 else 0, 1)
                max_flight_pct = round(np.max(flight_diff) if len(flight_diff) > 0 else 0, 1)
                
                if biometric_status == "success":
                    match_txt = "✅ Успіх"
                elif biometric_status == "warning":
                    match_txt = "⚠️ Попередження"
                elif biometric_status == "block":
                    match_txt = "🚫 Блокування"
                elif biometric_status == "failed":
                    match_txt = "❌ Невдача"
                else:
                    match_txt = biometric_status
                success_txt = "✅ Успіх" if success else "❌ Помилка"
                print(f"       {login_time} | {match_txt} | {success_txt}")
                print(f"         · Dwell: mean={f_dwell_mean}, std={f_dwell_std}, min={f_dwell_min}, max={f_dwell_max} (різниця: {max_dwell_pct}%)")
                print(f"         · Flight: mean={f_flight_mean}, std={f_flight_std}, min={f_flight_min}, max={f_flight_max} (різниця: {max_flight_pct}%)")

print("\n")
print("\nТаблиця roles:")
cursor.execute("SELECT * FROM roles")
roles = cursor.fetchall()

if not roles:
    print("❌ roles ПУСТА")
else:
    for r in roles:
        print(f"id={r[0]} | role_name={r[1]}")

# ---------------- USER_ROLES ----------------
print("\nТаблиця user_roles:")
cursor.execute("SELECT * FROM user_roles")
user_roles = cursor.fetchall()

if not user_roles:
    print("❌ user_roles ПУСТА")
else:
    for ur in user_roles:
        print(f"id={ur[0]} | username={ur[1]} | role_id={ur[2]}")

# ---------------- РЕСУРСИ ----------------
resources = view_resources()
print("\nРесурси у базі:")

for r in resources:
    filename, level = r
    print(f"{filename} | Рівень конфіденційності: {level}")

# ---------------- DAC ----------------
dac = view_dac()
print("\nDAC права:")

if not dac:
    print("Немає встановлених прав")
else:
    for d in dac:
        username, filename, r, w, s, x = d
        print(f"{username} -> {filename} | R:{r} W:{w} S:{s} X:{x}")


# ---------------- ROLE_PERMISSIONS ----------------
print("\nТаблиця role_permissions:")

cursor.execute("SELECT * FROM role_permissions")
role_perms = cursor.fetchall()

if not role_perms:
    print("❌ role_permissions ПУСТА")
else:
    for rp in role_perms:
        # rp: id, role_id, filename, can_read, can_write, can_save, can_execute, time_from, time_to
        id_, role_id, filename, r, w, s, x, t_from, t_to = rp
        print(f"id={id_} | role_id={role_id} | filename={filename} | "
              f"R:{r} W:{w} S:{s} X:{x} | time_from:{t_from} time_to:{t_to}")

conn.close()