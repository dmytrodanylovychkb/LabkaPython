# labs/lab02/task2.py
from collections import Counter
import csv
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)


def run_ssl_monitor(certs_path: str, days_warning: int, output_path: str, file_format: str):
    path = Path(certs_path)
    if not path.exists():
        logging.error(f"Файл сертифікатів не знайдено за шляхом: {path}")
        return

    logging.info(f"Loading SSL certificates data from {path}...")
    try:
        with open(path, "r", encoding="utf-8") as f:
            certs_data = json.load(f)
    except Exception as e:
        logging.error(f"Помилка читання JSON файлу: {e}")
        return

    logging.info(f"Audited {len(certs_data)} domain certificates.")
    print("\n=== Certificate Expiry & Safety Status ===")
    print(f"{'Domain':<25} | {'Issuer':<15} | {'Days Left':<10} | {'Status':<10} | {'Signature Alg'}")
    print("-" * 80)

    now = datetime.now(timezone.utc)
    issuers = []
    report_rows = []
    expired_count = 0
    warning_count = 0

    for cert in certs_data:
        # Використовуємо точні назви ключів із твого JSON
        domain = cert.get("domain", "unknown")
        issuer = cert.get("issuer", "Unknown")
        valid_to_str = cert.get("validTo", "")
        sig_alg = cert.get("signatureAlgorithm", "RSA-SHA256")
        issuers.append(issuer)

        try:
            valid_to_date = datetime.fromisoformat(valid_to_str).replace(tzinfo=timezone.utc)
        except ValueError:
            valid_to_date = now

        delta = valid_to_date - now
        days_left = delta.days

        # Визначення статусу
        if days_left < 0:
            status = "EXPIRED"
            expired_count += 1
        elif days_left <= days_warning:
            status = "WARNING"
            warning_count += 1
        else:
            status = "OK"

        # Перевірка на слабкі алгоритми через re
        is_weak = bool(re.search(r"sha1|md5", sig_alg, re.IGNORECASE))
        alg_display = f"{sig_alg} (WEAK)" if is_weak else sig_alg

        print(f"{domain:<25} | {issuer:<15} | {days_left:<10} | {status:<10} | {alg_display}")

        report_rows.append({
            "Domain": domain,
            "Issuer": issuer,
            "DaysLeft": days_left,
            "Status": status,
            "SignatureAlg": sig_alg
        })

    # Статистика видавців через Counter
    issuer_counts = Counter(issuers)
    print("\n=== Issuer Statistics ===")
    for issuer, count in issuer_counts.items():
        print(f"{issuer:<15} : {count}")

    if expired_count > 0 or warning_count > 0:
        logging.warning(f"{expired_count} certificate(s) EXPIRED! {warning_count} certificate(s) expiring within {days_warning} days!")

    # Збереження звіту
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if file_format.lower() == "json":
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_rows, f, ensure_ascii=False, indent=4)
    else:
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["Domain", "Issuer", "DaysLeft", "Status", "SignatureAlg"])
            writer.writeheader()
            writer.writerows(report_rows)

    logging.info(f"Report saved to {out_path}")