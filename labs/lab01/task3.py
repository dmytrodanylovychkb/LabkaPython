import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER


class ValidationError(Exception):
    pass


def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result_status = "failure"
        username = args[0] if args else kwargs.get("username", "unknown")

        try:
            res = func(*args, **kwargs)
            if res is True:
                result_status = "success"
            return res
        except Exception as e:
            result_status = f"failure ({type(e).__name__})"
            raise
        finally:
            log_dir = os.path.join(os.path.dirname(__file__), "data")
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "log.json")

            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args[1:]),
                "kwargs": kwargs,
            }

            logs = []
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []

            logs.append(log_entry)
            with open(log_path, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми!")

    min_len = 10
    if len(password) < min_len:
        raise ValidationError(f"Пароль занадто короткий. Мінімальна довжина: {min_len}")

    hasher = hashlib.new("sha3_384")
    raw_data = (password + salt).encode("utf-8")
    hasher.update(raw_data)
    return hasher.hexdigest()


def create_user(username: str, password: str) -> tuple:
    salt = f"{VARIANT_NUMBER:05d}"
    pwd_hash = generate_hash(password, salt)
    return (username, pwd_hash)


def create_users(users_list: list):
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)
    csv_path = os.path.join(data_dir, "users.csv")

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
            for uname, pwd in users_list:
                _, pwd_hash = create_user(uname, pwd)
                writer.writerow([uname, pwd_hash])
        print("[INFO] Базу даних users.csv успішно створено.")
    except (OSError, PermissionError) as e:
        print(f"[Помилка файлової системи]: {e}")


def read_users_db() -> list:
    csv_path = os.path.join(os.path.dirname(__file__), "data", "users.csv")
    users_db = []
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if row:
                    users_db.append((row[0], row[1]))
    except (OSError, PermissionError):
        print("[Попередження]: Файл бази даних ще не створено.")
    return users_db


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми під час входу!")

    users_db = read_users_db()
    salt = f"{VARIANT_NUMBER:05d}"
    input_hash = generate_hash(password, salt)

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == input_hash:
            return True
    return False


print("\nТестування входу в систему:")


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


users_db = [("admin_user", hash_password("SecurePass123!"))]

for u, p in [
    ("admin_user", "SecurePass123!"),
    ("admin_user", "WrongPassword!"),
    ("", "SecurePass123!"),
    ("admin_user", "short"),
]:
    try:
        print(f"Вхід {u} ({p}):", login(u, p, users_db))
    except (ValueError, ValidationError) as e:
        print(f"Очікуваний виняток: {e}")
    except Exception as e:  # noqa: BLE001
        print("Помилка:", e)


def run_task3():
    print(f"\n--- Завдання 3: Хешування та логування (Варіант {VARIANT_NUMBER}) ---")

    users_to_register = [
        ("admin_user", "SecurePass123!"),
        ("analyst_bob", "StrongPwd#2023"),
        ("dev_Alice", "Cryptographic1!"),
        ("guest_tom", "LongWelcome#9"),
        ("manager_sam", "Enterprise@2026"),
        ("support_kate", "HelpDeskKey#55"),
        ("auditor_paul", "CheckCompliance!"),
        ("tester_nick", "AutomationTest1"),
        ("system_root", "MasterKeyZ#009"),
        ("cloud_admin", "DevOpsSecure#77"),
    ]

    create_users(users_to_register)

    db = read_users_db()
    print(f"\n{'Логін':<20} | {'Хеш пароля (SHA3_384)'}")
    print("-" * 65)
    for u, h in db:
        print(f"{u:<20} | {h}")


if __name__ == "__main__":
    run_task3()
