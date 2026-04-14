import sqlite3
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from PIL import Image, ImageTk, ImageDraw
import os
import subprocess
import time
import json

from bruteforce import generate_charset, brute_force
from database.db import (
    get_user_roles, init_db, view_users, add_user, set_access_level, set_role, get_access_model,
    view_resources, set_confidentiality, set_access_model, set_dac_right, check_rbac_access, DB_NAME,
    record_login_attempt, get_login_attempts, get_user_biometric_stats
)
from auth.auth import set_password, check_complex_password, authenticate, get_password_type
from resources import can_access_full, get_resource_path
from behavioral_biometrics import enroll_user, authenticate_behavioral, load_profile, extract_keystroke_features

# ---------------- Custom Password Input ----------------

def get_password_with_checks(title, prompt):
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.geometry("300x150")
    tk.Label(dialog, text=prompt).pack(pady=10)
    entry = tk.Entry(dialog, show="*")
    entry.pack(pady=5)
    keystroke_events = []

    def on_press(event):
        if event.char:  # Only if char is not empty
            keystroke_events.append({'key': event.char, 'event': 'press', 'timestamp': time.time()})

    def on_release(event):
        if event.char:
            keystroke_events.append({'key': event.char, 'event': 'release', 'timestamp': time.time()})

    entry.bind('<KeyPress>', on_press)
    entry.bind('<KeyRelease>', on_release)

    # Prevent paste
    entry.bind('<Control-v>', lambda e: 'break')
    entry.bind('<<Paste>>', lambda e: 'break')

    # Disable right-click menu
    def disable_menu(event):
        return 'break'

    entry.bind('<Button-3>', disable_menu)

    result = [None, None]

    def on_ok():
        pwd = entry.get()
        # Old check for total time
        if keystroke_events:
            timestamps = [e['timestamp'] for e in keystroke_events]
            if timestamps:
                total_time = max(timestamps) - min(timestamps)
                if total_time < 0.5:  # less than 0.5 seconds - only block if extremely fast (bot/automation)
                    messagebox.showerror("Помилка", "Занадто швидке введення паролю")
                    return
        result[0] = pwd
        result[1] = keystroke_events
        dialog.destroy()

    def on_cancel():
        dialog.destroy()

    tk.Button(dialog, text="OK", command=on_ok).pack(side=tk.LEFT, padx=20)
    tk.Button(dialog, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=20)

    root.wait_window(dialog)
    return result[0], result[1]

# ---------------- ІНІЦІАЛІЗАЦІЯ ----------------
init_db()

root = tk.Tk()
root.title("TBD_Soltys")
root.geometry("700x600")

text_users = tk.Text(root, height=10)
text_users.pack()

# ------------------- АДМІН -------------------

def show_users():
    users = view_users()
    text_users.delete("1.0", tk.END)
    for u in users:
        pwd = u[1] if u[1] else "<не задано>"
        ptype = u[2] if u[2] else "<не задано>"
        role_list = get_user_roles(u[0])
        role = role_list[0] if role_list else "<не призначено>"
        
        text_users.insert(
            tk.END,
            f"{u[0]} | Пароль: {pwd} | Тип: {ptype} | Рівень доступу: {u[3]} | Роль: {role}\n"
        )
        
        # Показати статистику біометрії
        stats = get_user_biometric_stats(u[0])
        if stats["profile"]:
            profile = json.loads(stats["profile"])
            profile_short = [round(x, 4) for x in profile[:4]]
            text_users.insert(tk.END, f"   📊 Профіль: {profile_short}\n")
            
            if stats["attempts"]:
                text_users.insert(tk.END, f"   📋 Останні спроби входу:\n")
                for attempt in stats["attempts"]:
                    login_time, features_str, biometric_status, success = attempt
                    try:
                        features = json.loads(features_str)
                        features_short = [round(x, 4) for x in features[:4]]
                        if biometric_status == "success":
                            match_status = "✅ Успіх"
                        elif biometric_status == "warning":
                            match_status = "⚠️ Попередження"
                        elif biometric_status == "block":
                            match_status = "🚫 Блокування"
                        elif biometric_status == "failed":
                            match_status = "❌ Невдача"
                        else:
                            match_status = biometric_status
                        success_status = "✅" if success else "❌"
                        text_users.insert(tk.END, 
                            f"      {login_time} | {match_status} | {success_status} | {features_short}\n"
                        )
                    except:
                        pass
        
        text_users.insert(tk.END, "\n")

def create_user():
    username = simpledialog.askstring("Новий користувач", "Ім'я:")
    if username:
        if add_user(username):
            messagebox.showinfo("Успіх", "Користувач доданий")
            show_users()
        else:
            messagebox.showerror("Помилка", "Вже існує")

def change_password_admin():
    username = simpledialog.askstring("Пароль", "Користувач:")
    if not username:
        return
    ptype = simpledialog.askstring("Тип", "простий / складний")
    if ptype not in ["простий", "складний"]:
        messagebox.showerror("Помилка", "Невірний тип")
        return
    pwd, keystrokes = get_password_with_checks("Пароль", "Новий пароль:")
    if not pwd:
        return
    if ptype == "складний" and not check_complex_password(pwd):
        messagebox.showerror("Помилка", "Пароль слабкий")
        return
    expiry_days = simpledialog.askinteger("Термін дії", "Днів (30 за замовчуванням):", initialvalue=30)
    if expiry_days is None:
        expiry_days = 30
    if set_password(username, pwd, ptype, expiry_days):
        # Не реєструємо біометрію адміна! Тільки користувач повинен зареєструвати свою біометрію
        messagebox.showinfo("Успіх", "Пароль змінено. Користувач повинен змінити пароль на своїй машині для реєстрації біометрії")
        show_users()
    else:
        messagebox.showerror("Помилка", "Не вдалося змінити пароль (можливо, повторюється)")

def change_access():
    username = simpledialog.askstring("Рівень", "Користувач:")
    level = simpledialog.askstring("Новий рівень", "не таємно / таємно / цілком таємно")
    if set_access_level(username, level):
        messagebox.showinfo("Успіх", "Оновлено")
        show_users()
    else:
        messagebox.showerror("Помилка", "Не знайдено")

def assign_role():
    username = simpledialog.askstring("Призначити роль", "Користувач:")
    if not username:
        return
    role = simpledialog.askstring("Роль", "Reader / Editor / Admin:")
    if role not in ["Reader", "Editor", "Admin"]:
        messagebox.showerror("Помилка", "Невірна роль")
        return
    if set_role(username, role):
        messagebox.showinfo("Успіх", f"Роль {role} призначено {username}")
        show_users()
    else:
        messagebox.showerror("Помилка", "Користувача не знайдено")

def change_resource_confidentiality():
    filename = simpledialog.askstring("Файл", "Назва:")
    level = simpledialog.askstring("Рівень", "не таємно / таємно / цілком таємно")
    if set_confidentiality(filename, level):
        messagebox.showinfo("Успіх", "Оновлено")
    else:
        messagebox.showerror("Помилка", "Файл не знайдено")

def add_resource():
    filepath = filedialog.askopenfilename(title="Виберіть файл ресурсу")
    if filepath:
        filename = os.path.basename(filepath)
        import sqlite3
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO resources (filename) VALUES (?)", (filename,))
        conn.commit()
        conn.close()

        import shutil
        os.makedirs("Data", exist_ok=True)
        shutil.copy(filepath, os.path.join("Data", filename))

        messagebox.showinfo("Успіх", f"Додано ресурс {filename}")

# ------------------- DAC -------------------

def set_dac_ui():
    username = simpledialog.askstring("DAC", "Користувач:")
    filename = simpledialog.askstring("DAC", "Файл:")

    if not username or not filename:
        return

    # --- перевірка юзера ---
    users = [u[0] for u in view_users()]
    if username not in users:
        messagebox.showerror("Помилка", "Користувача не існує")
        return

    # --- перевірка файлу ---
    resources = view_resources()
    resource_names = [r[0] for r in resources]

    if filename not in resource_names:
        messagebox.showerror("Помилка", "Файл не знайдено в базі")
        return

    path = get_resource_path(filename)
    if not os.path.exists(path):
        messagebox.showerror("Помилка", "Файл відсутній")
        return

    # --- ПРАВА ---
    r_var = tk.IntVar()
    w_var = tk.IntVar()
    s_var = tk.IntVar()
    x_var = tk.IntVar()

    # --- ЧАС ---
    t_from = simpledialog.askinteger("Час", "З якої години (0-23):")
    t_to = simpledialog.askinteger("Час", "До якої години (0-23):")

    if t_from is None or t_to is None:
        return

    if not (0 <= t_from <= 23 and 0 <= t_to <= 23):
        messagebox.showerror("Помилка", "Невірний час")
        return

    def apply_dac():
        set_dac_right(
            username,
            filename,
            r_var.get(),
            w_var.get(),
            s_var.get(),
            x_var.get(),
            t_from,
            t_to
        )
        messagebox.showinfo("Успіх", f"Права діють з {t_from} до {t_to}")
        dac_win.destroy()

    dac_win = tk.Toplevel()
    dac_win.title("DAC")

    tk.Checkbutton(dac_win, text="Читання", variable=r_var).pack()
    tk.Checkbutton(dac_win, text="Запис", variable=w_var).pack()
    tk.Checkbutton(dac_win, text="Збереження", variable=s_var).pack()
    tk.Checkbutton(dac_win, text="Виконання", variable=x_var).pack()

    tk.Button(dac_win, text="Застосувати", command=apply_dac).pack()

# ------------------- МОДЕЛІ ДОСТУПУ -------------------

def choose_model():
    model = simpledialog.askstring("Модель", "MANDATORY / DAC / RBAC")
    if model not in ["MANDATORY", "DAC", "RBAC"]:
        messagebox.showerror("Помилка", "Невірно")
        return
    set_access_model(model)
    messagebox.showinfo("Успіх", f"Модель: {model}")

# ------------------- АВТЕНТИФІКАЦІЯ -------------------

def auth_user():
    username = simpledialog.askstring("Логін", "Введіть логін:")
    if not username:
        return

    attempts = 0
    while attempts < 3:
        pwd, keystrokes = get_password_with_checks("Пароль", "Введіть пароль:")
        if not pwd:
            return

        # Завжди отримуємо біометричні дані для запису
        keystroke_features_json = json.dumps([round(float(x), 6) for x in extract_keystroke_features(keystrokes)])

        user = authenticate(username, pwd)

        if user:
            # Користувач існує і пароль правильний - перевіряємо біометрію
            profile = load_profile(username)
            
            biometric_match = None
            success = 1
            allow_access = True
            
            if profile:  # Профіль існує - перевіряємо біометрію
                biometric_status, features, profile_data = authenticate_behavioral(username, keystrokes)
                
                if biometric_status == "success":
                    biometric_match = "success"
                    # Тихий успіх - нічого не показуємо
                elif biometric_status == "warning":
                    biometric_match = "warning"
                    messagebox.showwarning("Попередження", 
                        "Поведінка при введенні відрізняється від вашого профіля\n"
                        "(Це може бути стрес, інше середовище або природні варіації)\n"
                        "Але вхід дозволено, оскільки пароль вірний")
                elif biometric_status == "block":
                    biometric_match = "block"
                    success = 0
                    allow_access = False
                    messagebox.showerror("Блокування доступу", 
                        "Поведінка при введенні значно відрізняється від вашого профіля\n"
                        "Це може бути спроба вторгнення або підміни користувача\n"
                        "Доступ заблоковано для безпеки")
            else:  # Профіль не існує - реєструємо під час першого входу
                enroll_user(username, keystrokes)
                biometric_match = "success"  # Перший вхід завжди совпадає
                messagebox.showinfo("Інформація", 
                    "Ваш поведінковий профіль зареєстрований!\n"
                    "При наступних входах буде перевіряться біометрія")
            
            if allow_access:
                # Записати спробу входу
                record_login_attempt(username, keystroke_features_json, biometric_match, success)
                
                users = view_users()
                level = next((u[3] for u in users if u[0] == username), "не таємно")
                roles = get_user_roles(username)
                role = roles[0] if roles else "<не призначено>"
                messagebox.showinfo("Успіх", f"Вітаємо {username}")
                open_user_screen(username, level, role)
                return
            else:
                # Записати невдалу спробу входу через біометрію
                record_login_attempt(username, keystroke_features_json, biometric_match, success)
                return
        else:
            # Пароль неправильний - але все одно записуємо біометричні дані для аналізу
            record_login_attempt(username, keystroke_features_json, "failed", 0)
            
            attempts += 1
            if attempts < 3:
                messagebox.showerror("Помилка", f"Невірно. Спроба {attempts}/3")
            else:
                messagebox.showerror("Помилка", "Забагато спроб. Доступ заблоковано.")
                # The authenticate function already handles blocking after 5 attempts

# ------------------- КОРИСТУВАЧ -------------------

def open_user_screen(username, user_level, role):
    root.withdraw()
    win = tk.Toplevel()
    win.title(username)

    tk.Label(win, text=f"{username} | {user_level} | Роль: {role}").pack()

    tk.Button(win, text="Ресурси",
              command=lambda: show_resources(username, user_level, role)).pack(pady=5)
    tk.Button(win, text="Змінити пароль",
              command=lambda: change_password_user(username)).pack(pady=5)
    tk.Button(win, text="Вийти",
              command=lambda: logout(win)).pack(pady=5)

def change_password_user(username):
    # Get current password type
    current_ptype = get_password_type(username)
    if not current_ptype:
        messagebox.showerror("Помилка", "Не вдалося отримати тип пароля")
        return
    ptype = current_ptype  # Use current type, user cannot change it

    pwd, keystrokes = get_password_with_checks("Пароль", "Новий пароль:")
    if not pwd:
        return

    if ptype == "складний" and not check_complex_password(pwd):
        messagebox.showerror("Помилка", "Пароль слабкий")
        return

    expiry_days = 30  # Default for users, only admin can change
    if set_password(username, pwd, ptype, expiry_days):
        enroll_user(username, keystrokes)  # Реєструємо біометрію користувача
        messagebox.showinfo("Успіх", "Пароль змінено\n✅ Ваш поведінковий профіль оновлено!")
    else:
        messagebox.showerror("Помилка", "Не вдалося змінити пароль (можливо, повторюється)")

# ------------------- РЕСУРСИ -------------------

def show_resources(username, user_level, role):
    resources = view_resources()
    res_window = tk.Toplevel()

    for filename, conf_level in resources:
        model = get_access_model()

        if model == "RBAC":
            allowed = check_rbac_access(username, filename, "read")
        else:
            allowed = can_access_full(username, user_level, conf_level, filename, "read")

        if allowed:
            tk.Button(
                res_window,
                text=f"{filename}",
                command=lambda f=filename: open_file(username, user_level, f)
            ).pack()
        else:
            tk.Label(res_window, text=f"{filename} ❌").pack()

def open_file(username, user_level, filename):
    path = get_resource_path(filename)
    model = get_access_model()

    def check(action):
        if model == "RBAC":
            return check_rbac_access(username, filename, action)
        return can_access_full(username, user_level, "", filename, action)

    if filename.lower().endswith((".png", ".jpg", ".jpeg")):
        if not check("read"):
            messagebox.showerror("Помилка", "Немає права")
            return
        open_image_editor(username, filename, path)

    elif filename.endswith(".exe"):
        if not check("execute"):
            messagebox.showerror("Помилка", "Немає права")
            return
        subprocess.Popen(path, shell=True)

    elif filename.lower().endswith((".txt", ".log", ".csv")):
        if not check("read"):
            messagebox.showerror("Помилка", "Немає права читання")
            return
        open_text_editor(username, user_level, filename, path)

    else:
        if not check("read"):
            messagebox.showerror("Помилка", "Немає права")
            return
        os.startfile(path)
# ------------------- ТЕКСТОВИЙ РЕДАКТОР -------------------

def open_text_editor(username, user_level, filename, path):
    editor = tk.Toplevel()
    editor.title(filename)

    text = tk.Text(editor, wrap="word")
    text.pack(expand=True, fill="both")

    with open(path, "r", encoding="utf-8") as f:
        text.insert("1.0", f.read())

    can_write = can_access_full(username, user_level, "", filename, "write")
    can_save = can_access_full(username, user_level, "", filename, "save")

    if not can_write:
        text.config(state="disabled")

    def save_file():
        if not can_save:
            messagebox.showerror("Помилка", "Немає права зберігати")
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(text.get("1.0", tk.END))

        messagebox.showinfo("Успіх", "Файл збережено")

    tk.Button(editor, text="Зберегти", command=save_file).pack()

def set_role_permission_ui():
    role = simpledialog.askstring("Роль", "Введіть роль (Reader/Editor/Admin):")
    filename = simpledialog.askstring("Файл", "Назва файлу:")
    if not role or not filename:
        return

    r_var = tk.IntVar()
    w_var = tk.IntVar()
    s_var = tk.IntVar()
    x_var = tk.IntVar()

    t_from = simpledialog.askinteger("Час початку", "З якої години (0-23):", minvalue=0, maxvalue=23)
    t_to = simpledialog.askinteger("Час закінчення", "До якої години (0-23):", minvalue=0, maxvalue=23)

    def apply_permissions():
        from database.db import DB_NAME
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM roles WHERE role_name=?", (role,))
        role_id = cursor.fetchone()[0]

        cursor.execute("""
        INSERT INTO role_permissions
        (role_id, filename, can_read, can_write, can_save, can_execute, time_from, time_to)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(role_id, filename) DO UPDATE SET
            can_read=excluded.can_read,
            can_write=excluded.can_write,
            can_save=excluded.can_save,
            can_execute=excluded.can_execute,
            time_from=excluded.time_from,
            time_to=excluded.time_to
        """, (role_id, filename, r_var.get(), w_var.get(), s_var.get(), x_var.get(), t_from, t_to))
        conn.commit()
        conn.close()
        messagebox.showinfo("Успіх", "Права ролі застосовано")
        perm_win.destroy()

    perm_win = tk.Toplevel()
    perm_win.title(f"Права ролі {role}")

    tk.Checkbutton(perm_win, text="Читання", variable=r_var).pack()
    tk.Checkbutton(perm_win, text="Запис", variable=w_var).pack()
    tk.Checkbutton(perm_win, text="Збереження", variable=s_var).pack()
    tk.Checkbutton(perm_win, text="Виконання", variable=x_var).pack()
    tk.Button(perm_win, text="Застосувати", command=apply_permissions).pack()

# ------------------- РЕДАГУВАННЯ ЗОБРАЖЕНЬ -------------------

def open_image_editor(username, filename, path):
    editor = tk.Toplevel()
    editor.title(filename)

    img = Image.open(path)
    tk_img = ImageTk.PhotoImage(img)

    canvas = tk.Canvas(editor, width=img.width, height=img.height)
    canvas.pack()

    canvas.img = tk_img
    canvas.create_image(0, 0, anchor="nw", image=tk_img)

    draw = ImageDraw.Draw(img)

    can_write = can_access_full(username, "", "", filename, "write")
    can_save = can_access_full(username, "", "", filename, "save")

    last_x = last_y = None

    def motion(event):
        nonlocal last_x, last_y
        if last_x and last_y and can_write:
            canvas.create_line(last_x, last_y, event.x, event.y, fill="red", width=3)
            draw.line([last_x, last_y, event.x, event.y], fill="red", width=3)
        last_x, last_y = event.x, event.y

    def reset(event):
        nonlocal last_x, last_y
        last_x = last_y = None

    canvas.bind("<B1-Motion>", motion)
    canvas.bind("<ButtonRelease-1>", reset)

    def save_changes():
        if can_save:
            img.save(path)
            messagebox.showinfo("Успіх", "Збережено")
        else:
            messagebox.showerror("Помилка", "Немає права зберігати")

    tk.Button(editor, text="Зберегти", command=save_changes).pack()

def brute_force_ui():
    from tkinter import simpledialog, messagebox

    username = simpledialog.askstring("Brute Force", "Ім'я користувача:")
    if not username:
        return

    # --- 5 режимів ---
    mode = simpledialog.askstring(
        "Режим",
        "Оберіть режим:\n"
        "none - нічого не відомо\n"
        "exact - точна довжина\n"
        "approx - довжина ±1\n"
        "exact_charset - точна довжина + набори символів\n"
        "approx_charset - довжина ±1 + набори символів"
    )

    if mode not in ["none", "exact", "approx", "exact_charset", "approx_charset"]:
        messagebox.showerror("Помилка", "Невірний режим")
        return

    # --- довжина ---
    length = None
    if mode in ["exact", "approx", "exact_charset", "approx_charset"]:
        length = simpledialog.askinteger("Довжина", "Введіть довжину пароля:")

    # --- charset ---
    if mode in ["exact_charset", "approx_charset"]:
        use_latin = messagebox.askyesno("Набори", "Використовується латиниця?")
        use_digits = messagebox.askyesno("Набори", "Використовуються цифри?")
        use_symbols = messagebox.askyesno("Набори", "Використовуються спецсимволи?")

        charset = generate_charset(
            use_latin=use_latin,
            use_digits=use_digits,
            use_symbols=use_symbols
        )

    else:
        complexity = simpledialog.askstring("Складність", "simple / complex")

        if complexity not in ["simple", "complex"]:
            messagebox.showerror("Помилка", "Невірна складність")
            return

        if complexity == "simple":
            charset = generate_charset(True, False, True, False)
        else:
            charset = generate_charset(True, False, True, True)

    # --- запуск ---
    pwd, elapsed, attempts = brute_force(username, charset, mode, length)

    if pwd:
        messagebox.showinfo(
            "УСПІХ",
            f"Пароль: {pwd}\nЧас: {elapsed:.2f} сек\nСпроб: {attempts}"
        )
    else:
        messagebox.showwarning(
            "НЕ ЗНАЙДЕНО",
            f"Час: {elapsed:.2f} сек\nСпроб: {attempts}"
        )
# ------------------- ЛОГІН/ВИХІД -------------------

def logout(win):
    win.destroy()
    root.deiconify()

# ------------------- КНОПКИ -------------------

tk.Button(root, text="Показати користувачів", command=show_users).pack(pady=5)
tk.Button(root, text="Створити користувача", command=create_user).pack(pady=5)
tk.Button(root, text="Змінити пароль (адмін)", command=change_password_admin).pack(pady=5)
tk.Button(root, text="Змінити рівень доступу", command=change_access).pack(pady=5)
tk.Button(root, text="Призначити роль користувачу", command=assign_role).pack(pady=5)
tk.Button(root, text="Налаштувати права ролі", command=set_role_permission_ui).pack(pady=5)
tk.Button(root, text="Змінити мітку ресурсу", command=change_resource_confidentiality).pack(pady=5)
tk.Button(root, text="Додати ресурс", command=add_resource).pack(pady=5)
tk.Button(root, text="Обрати модель доступу", command=choose_model).pack(pady=5)
tk.Button(root, text="Видати DAC права", command=set_dac_ui).pack(pady=5)
tk.Button(root, text="Brute Force тест", command=brute_force_ui).pack(pady=5)
tk.Button(root, text="Автентифікація", command=auth_user).pack(pady=5)

root.mainloop()