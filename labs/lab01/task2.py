import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import VARIANT_NUMBER


def check_access():
    users = {
        "iot_specialist": {
            "role": "iot_security",
            "clearance": 3,
            "department": "IoT",
            "active": True,
        },
        "mobile_analyst": {
            "role": "mobile_security",
            "clearance": 3,
            "department": "Mobile",
            "active": True,
        },
        "web_developer": {
            "role": "web_developer",
            "clearance": 2,
            "department": "Web",
            "active": True,
        },
        "api_consumer": {
            "role": "api_user",
            "clearance": 2,
            "department": "Integration",
            "active": True,
        },
        "demo_account": {
            "role": "demonstration",
            "clearance": 1,
            "department": "Demo",
            "active": False,
        },
    }
    resources = [
        ("iot_firmware", 3),
        ("mobile_policies", 3),
        ("web_applications", 2),
        ("api_gateway", 2),
        ("device_certificates", 3),
        ("app_store", 1),
        ("vulnerability_database", 3),
        ("device_management", 3),
        ("integration_docs", 2),
        ("demo_content", 1),
    ]
    security_levels = ("Consumer", "Business", "Enterprise", "Critical Systems")
    blocked_users = {"demo_account", "compromised_device", "malicious_app"}

    print(f"\n--- Система контролю доступу (Варіант {VARIANT_NUMBER}) ---")
    print("Список ресурсів системи:")
    for res_name, lvl in resources:
        level_name = (
            security_levels[lvl - 1] if 1 <= lvl <= len(security_levels) else "Unknown"
        )
        print(f" - Ресурс: {res_name:<25} | Рівень: {lvl} ({level_name})")

    print("\nРезультати перевірки доступу:")
    for username, u_info in users.items():
        for res_name, res_level in resources:
            if username not in users:
                decision = "DENY (User not found)"
            elif username in blocked_users:
                decision = "DENY (User is blocked)"
            elif not u_info.get("active", False):
                decision = "DENY (Account inactive)"
            elif u_info["clearance"] >= res_level:
                decision = "ALLOW"
            else:
                decision = "DENY (Insufficient clearance)"

            print(f"user={username:<15} resource={res_name:<22} -> {decision}")


if __name__ == "__main__":
    check_access()
