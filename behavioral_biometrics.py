import sqlite3
import json
import numpy as np
from database.db import DB_NAME

def extract_keystroke_features(keystroke_events):
    """
    Extract features from keystroke events.
    keystroke_events: list of {'key': str, 'event': 'press'/'release', 'timestamp': float}
    """
    dwell_times = []
    flight_times = []
    prev_release = None
    press_times = {}

    for event in keystroke_events:
        key = event['key']
        if event['event'] == 'press':
            press_times[key] = event['timestamp']
        elif event['event'] == 'release':
            if key in press_times:
                dwell = event['timestamp'] - press_times[key]
                dwell_times.append(dwell)
                if prev_release is not None:
                    flight = press_times[key] - prev_release  # flight is from prev release to next press
                    flight_times.append(flight)
                prev_release = event['timestamp']

    features = []
    if dwell_times:
        features.extend([
            np.mean(dwell_times),
            np.std(dwell_times),
            np.min(dwell_times),
            np.max(dwell_times)
        ])
    else:
        features.extend([0, 0, 0, 0])

    if flight_times:
        features.extend([
            np.mean(flight_times),
            np.std(flight_times),
            np.min(flight_times),
            np.max(flight_times)
        ])
    else:
        features.extend([0, 0, 0, 0])

    return features

def save_profile(username, features):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO behavioral_profiles (username, keystroke_features) VALUES (?, ?)",
                   (username, json.dumps(features)))
    conn.commit()
    conn.close()

def load_profile(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT keystroke_features FROM behavioral_profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None

def enroll_user(username, keystroke_events):
    features = extract_keystroke_features(keystroke_events)
    save_profile(username, features)

def authenticate_behavioral(username, keystroke_events):
    features = extract_keystroke_features(keystroke_events)
    profile = load_profile(username)
    if not profile:
        return "success", features, None  # No profile, allow, return current features

    profile = np.array(profile)
    features = np.array(features)
    diff = np.abs(features - profile)
    
    # Окремо обробляємо dwell (перші 4 параметри) та flight (останні 4 параметри)
    # Dwell times більш стабільні - основний критерій
    # Flight times варіативні, але екстремальні різниці означають підозрілу активність
    
    dwell_diff = diff[:4] / (np.abs(profile[:4]) + 1e-10)
    flight_diff = diff[4:] / (np.abs(profile[4:]) + 1e-10)
    
    max_dwell_percent = np.max(dwell_diff) * 100 if len(dwell_diff) > 0 else 0
    max_flight_percent = np.max(flight_diff) * 100 if len(flight_diff) > 0 else 0
    
    # Блокування при екстремально різних flight times (можливо автоматизація/бот)
    if max_flight_percent > 400:
        return "block", features, profile
    
    # Основна перевірка на dwell time
    if max_dwell_percent < 70 and max_flight_percent < 200:
        return "success", features, profile
    elif max_dwell_percent < 100 and max_flight_percent < 300:
        return "warning", features, profile
    else:
        return "block", features, profile