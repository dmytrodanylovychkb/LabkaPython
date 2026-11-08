# labs/lab02/task1.py
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import os
import re

SESSION_TIMEOUT_SEC = 900  # 15 хвилин таймаут за замовчуванням
ITERATIONS = 100_000


class User:
    def __init__(self, username: str, email: str, role: str, active: bool = True):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash: bytes = b""
        self.__password_salt: bytes = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        # Перевірка формату email за допомогою регулярного виразу
        email_regex = r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, value):
            raise ValueError(f"Невірний формат email: {value}")
        self._email = value

    def set_password(self, password: str):
        if not password or len(password) < 6:
            raise ValueError("Пароль занадто короткий або порожній.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash or not self.__password_salt:
            return False
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, ITERATIONS
        )
        return hmac.compare_digest(test_hash, self.__password_hash)

    def deactivate(self):
        self.active = False

    def __str__(self) -> str:
        return f"User(username={self.username}, role={self.role}, active={self.active})"


class Admin(User):
    def __init__(self, username: str, email: str, role: str = "administrator", active: bool = True,
                 permissions: set = None):
        super().__init__(username, email, role, active)
        self.permissions: set = set(permissions) if permissions is not None else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return f"Admin(username={self.username}, role={self.role}, permissions={list(self.permissions)})"


class Session:
    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Timeout повинен бути додатним числом.")
        now = datetime.now(timezone.utc)
        elapsed = (now - self.last_activity).total_seconds()
        return elapsed <= timeout_sec


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.logs: list[AuditRecord] = []

    def add_log(self, username: str, action: str):
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action
        )
        self.logs.append(record)

    def show_all(self):
        for log in self.logs:
            print(f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] User: {log.username} -> Action: {log.action}")


class UserAccount:
    def __init__(self, user: User, session: Session = None, audit_log: AuditLog = None):
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(username, "login_failure_account_inactive")
            return False
        if self.user.username == username and self.user.check_password(password):
            self.session = Session(ip)
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        try:
            active = self.session.is_active(SESSION_TIMEOUT_SEC)
            if active:
                self.session.touch()
            return active
        except Exception:
            return False

    def logout(self):
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення повинно бути екземпляром User")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення повинно бути екземпляром Session")
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Значення повинно бути екземпляром AuditLog")
            self.audit_log = value
        else:
            raise KeyError(f"Невідомий або заборонений ключ для запису: {key}")


def run_demo():
    print("=== Демонстрація ООП (Завдання 1) ===")
    user = User("admin_test", "admin.sys@example.com", "operator")
    user.set_password("SecureP@ss123")

    account = UserAccount(user)

    # Спроба входу
    success = account.login("admin_test", "SecureP@ss123", "192.168.1.50")
    print(f"Успішний вхід: {success}")
    print(f"Автентифіковано: {account.is_authenticated()}")

    # Зміна email через property з перевіркою
    try:
        user.email = "new_admin_mail@example.com"
        print(f"Новий email успішно встановлено: {user.email}")
    except ValueError as e:
        print(f"Помилка валідації email: {e}")

    # Перевірка AuditLog
    print("\n--- Журнал аудиту ---")
    account.audit_log.show_all()

    # Вихід
    account.logout()
    print(f"Після logout автентифіковано: {account.is_authenticated()}")