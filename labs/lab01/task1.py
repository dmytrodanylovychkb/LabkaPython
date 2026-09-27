import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def analyze_passwords():
    passwords = [
        "S0cial@Engineer",
        "basic",
        "Phish1ng@D3tect",
        "client",
        "Ransomwar3@Protect",
        "general",
        "Zero@D4y",
        "generic",
        "Bug@B0unty",
        "standard123",
    ]
    criteria = {
        "min_length": 11,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }
    forbidden_passwords = {
        "basic",
        "client",
        "general",
        "generic",
        "standard123",
        "guest",
    }

    random.seed(42)
    extra_indexes = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    extended_passwords = passwords + [passwords[i] for i in extra_indexes]

    results = []
    for pwd in extended_passwords:
        if pwd in forbidden_passwords or len(pwd) < criteria["min_length"]:
            status = "Заборонений / Недостатня довжина"
            results.append((pwd, status))
            continue

        has_digit = any(char.isdigit() for char in pwd)
        has_upper = any(char.isupper() for char in pwd)
        has_special = any(not char.isalnum() for char in pwd)
        has_lower = any(char.islower() for char in pwd)

        meets_all = has_digit and has_upper and has_special and has_lower
        is_unique = extended_passwords.count(pwd) == 1

        if meets_all and len(pwd) >= criteria["min_length"] + 4 and is_unique:
            status = "Дуже сильний"
        elif meets_all and len(pwd) < criteria["min_length"] + 4:
            status = "Сильний"
        elif meets_all or (has_digit or has_upper or has_special or has_lower):
            status = "Середній" if (has_digit and has_upper) else "Слабкий"
        else:
            status = "Слабкий"

        results.append((pwd, status))

    print(f"\n--- Аналіз паролів (Варіант {VARIANT_NUMBER}) ---")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME}\n")
    print(f"{'Пароль':<25} | {'Статус безпеки'}")
    print("-" * 45)
    for pwd, status in results:
        print(f"{pwd:<25} | {status}")


if __name__ == "__main__":
    analyze_passwords()
