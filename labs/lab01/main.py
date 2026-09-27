import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from task1 import analyze_passwords
from task2 import check_access
from task3 import run_task3

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    print("=" * 60)
    print(" ЛАБОРАТОРНА РОБОТА №1 ")
    print(f" Студент: {STUDENT_NAME}")
    print(f" Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 60)

    analyze_passwords()
    check_access()
    run_task3()

    print("\n" + "=" * 60)
    print(" Усі завдання лабораторної роботи успішно виконано!")
    print("=" * 60)


if __name__ == "__main__":
    main()
