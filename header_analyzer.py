
import requests
import argparse


SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps protect against XSS and content injection.",

    "Strict-Transport-Security":
        "Enforces HTTPS connections.",

    "X-Frame-Options":
        "Helps protect against clickjacking.",

    "X-Content-Type-Options":
        "Prevents MIME-type sniffing.",

    "Referrer-Policy":
        "Controls referrer information sharing.",

    "Permissions-Policy":
        "Controls access to browser features."
}


def analyze_website(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print("\n" + "=" * 60)
    print("          HTTP SECURITY HEADER ANALYZER")
    print("=" * 60)

    print(f"Target: {url}")

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        print(f"\nHTTP Status: {response.status_code}")
        print(f"Final URL: {response.url}")

        print("\n========== SECURITY ANALYSIS ==========")

        present = 0
        missing = 0

        for header, description in SECURITY_HEADERS.items():

            value = response.headers.get(header)

            if value:
                print(f"\n[FOUND] {header}")
                print(f"Value: {value}")
                present += 1

            else:
                print(f"\n[MISSING] {header}")
                print(f"Purpose: {description}")
                missing += 1

        print("\n========== SUMMARY ==========")
        print(f"Headers Found: {present}")
        print(f"Headers Missing: {missing}")
        print("=" * 60)

    except requests.exceptions.RequestException as error:
        print(f"\n[ERROR] Unable to connect: {error}")


def main():

    parser = argparse.ArgumentParser(
        description="HTTP Security Header Analyzer"
    )

    parser.add_argument(
        "url",
        help="Website URL to analyze"
    )

    args = parser.parse_args()

    analyze_website(args.url)


if __name__ == "__main__":
    main()
