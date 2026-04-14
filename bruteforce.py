import itertools
import time
from auth.auth import authenticate

# --- Набори символів ---
LATIN_LOWER = "abcdefghijklmnopqrstuvwxyz"
LATIN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"

def generate_charset(use_latin=True, use_cyrillic=False, use_digits=True, use_symbols=False):
    charset = ""
    if use_latin:
        charset += LATIN_LOWER + LATIN_UPPER
    if use_digits:
        charset += DIGITS
    return charset

def brute_force(username, charset, mode="none", length=None):
    import itertools
    import time
    from auth.auth import authenticate

    if not charset:
        return None, 0, 0

    # --- визначення довжини ---
    if mode in ["exact", "exact_charset"] and length:
        min_len = max_len = length
    elif mode in ["approx", "approx_charset"] and length:
        min_len = max(1, length - 1)
        max_len = length + 1
    else:
        min_len = 1
        max_len = 6

    start_time = time.time()
    attempts = 0

    for l in range(min_len, max_len + 1):
        for attempt in itertools.product(charset, repeat=l):
            attempts += 1
            pwd = "".join(attempt)

            if authenticate(username, pwd):
                return pwd, time.time() - start_time, attempts

            # лог (щоб не виглядало як зависання)
            if attempts % 100000 == 0:
                print(f"Спроб: {attempts}")

    return None, time.time() - start_time, attempts


