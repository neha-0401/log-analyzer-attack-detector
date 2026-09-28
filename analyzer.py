

# ╔══════════════════════════════════════════════════════════════╗
# ║     YOUR ASCII ART HEADER HERE                             ║
# ║                                                            ║
# ║     LOG ANALYZER & ATTACK DETECTOR                         ║
# ║     Cybersecurity Monitoring Project                        ║
# ╚══════════════════════════════════════════════════════════════╝

print(r"""
▓     ▄▀▀▄  ▓▀▀▀▀      ▄▀▀▀▄ ▓▀▀▄  ▄▀▀▀▄ ▓     █   █ ▀▀▀▀▀ ▄▀▀▀▀ █▀▀▀▄
░     ▒   ▀ ▒ ▀▀▀ ▀▀▀▀ ▓▄▄▄▀ ▒   ▀ ▓▄▄▄▀ ░      ▀▀▀▀ ▄▀▀▀▀ ▓▀▀   ▓▄▄▄▀
""")

import re



LOG_FILE = "security.log"
THRESHOLD = 5


def analyze_log():

    failed_attempts = {}

    total_success = 0
    total_failed = 0

    with open(LOG_FILE, "r") as file:

        for line in file:

            ip_match = re.search(
                r'ip=(\d+\.\d+\.\d+\.\d+)',
                line
            )

            if not ip_match:
                continue

            ip = ip_match.group(1)

            if "Login failed" in line:

                total_failed += 1

                if ip not in failed_attempts:
                    failed_attempts[ip] = 0

                failed_attempts[ip] += 1

            elif "Login successful" in line:

                total_success += 1

    return (
        total_success,
        total_failed,
        failed_attempts
    )


def display_report():

    success, failed, attempts = analyze_log()

    print("\n================================")
    print("       SECURITY LOG REPORT")
    print("================================")

    print(f"\nSuccessful logins : {success}")
    print(f"Failed logins     : {failed}")

    print("\nFailed attempts by IP")
    print("--------------------------------")

    for ip, count in attempts.items():

        if count >= THRESHOLD:

            print(
                f"{ip:<18} "
                f"{count} attempts 🚨 SUSPICIOUS"
            )

        else:

            print(
                f"{ip:<18} "
                f"{count} attempts"
            )


def main():

    while True:

        print("\n==============================")
        print("      LOG ANALYZER")
        print("==============================")

        print("1. Analyze log")
        print("2. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":

            try:

                display_report()

            except FileNotFoundError:

                print("❌ Log file not found.")

        elif choice == "2":

            print("Goodbye!")
            break

        else:

            print("❌ Invalid option.")


if __name__ == "__main__":
    main()
