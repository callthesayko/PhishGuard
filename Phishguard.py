
import argparse
import json
import re
from urllib.parse import urlsplit, unquote

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "ow.ly"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "password", "signin",
    "account", "wallet", "recover", "confirm"
}

BRANDS = {
    "paypal", "google", "microsoft", "apple",
    "amazon", "instagram", "facebook", "binance"
}


def analyze_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("URL cannot be empty.")

    candidate = (
        raw_url if "://" in raw_url
        else "https://" + raw_url
    )

    parts = urlsplit(candidate)

    if parts.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parts.hostname:
        raise ValueError("Invalid URL: hostname not found.")

    host = parts.hostname.lower().rstrip(".")
    findings = []

    def warn(code, points, title, explanation):
        findings.append({
            "code": code,
            "points": points,
            "title": title,
            "explanation": explanation
        })

    if parts.scheme == "http":
        warn(
            "no_https", 12,
            "HTTP instead of HTTPS",
            "The URL does not use HTTPS. This alone does not prove phishing."
        )

    if "@" in parts.netloc:
        warn(
            "userinfo", 22,
            "Potentially confusing URL syntax",
            "An @ symbol appears in the authority section. Inspect the hostname."
        )

    if host.startswith("xn--") or ".xn--" in host:
        warn(
            "punycode", 15,
            "Internationalized hostname",
            "Check for lookalike characters in the domain."
        )

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        warn(
            "ip_address", 14,
            "IP address used as hostname",
            "An IP-based URL can be legitimate, but deserves context."
        )

    if len(host) > 45:
        warn(
            "long_hostname", 7,
            "Long hostname",
            "A long hostname can make the important domain harder to spot."
        )

    if len(host.split(".")) >= 5:
        warn(
            "many_subdomains", 7,
            "Many subdomains",
            "Check which domain actually controls this hostname."
        )

    if host in SHORTENERS:
        warn(
            "shortener", 10,
            "URL shortener",
            "The final destination is hidden until the link is expanded."
        )

    decoded = unquote(
        (parts.path or "") + "?" + (parts.query or "")
    ).lower()

    matched = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", decoded)
    )

    if matched:
        warn(
            "suspicious_terms", min(15, 5 + 2 * len(matched)),
            "Account-related terms in URL",
            "Found: " + ", ".join(matched)
            + ". These words can also appear on legitimate websites."
        )

    domain_labels = host.split(".")
    registered_domain = ".".join(domain_labels[-2:]) if len(domain_labels) >= 2 else host
    possible_brands = [
        brand for brand in BRANDS
        if brand in host.replace("-", "")
        and registered_domain != brand + ".com"
    ]

    if possible_brands:
        warn(
            "brand_keyword", 10,
            "Possible brand-name lookalike",
            "Brand terms found: " + ", ".join(sorted(possible_brands))
            + ". This heuristic can produce false positives."
        )

    score = min(100, sum(item["points"] for item in findings))

    if score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "url": candidate,
        "hostname": host,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "limitations": [
            "This is a heuristic, not a verdict.",
            "The URL is not opened and no network requests are made.",
            "A low score does not mean a URL is safe."
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard - heuristic URL risk checker"
    )
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--json", action="store_true",
                        help="Print JSON report")
    args = parser.parse_args()

    url = args.url or input("Enter URL (it will NOT be opened): ")

    try:
        report = analyze_url(url)
    except ValueError as error:
        parser.error(str(error))

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    print("\n=== PhishGuard Report ===")
    print("Hostname:", report["hostname"])
    print(
        f'Risk: {report["risk_level"]} '
        f'({report["risk_score"]}/100)'
    )

    print("\nFindings:")
    if not report["findings"]:
        print("- No configured warning signals detected.")

    for finding in report["findings"]:
        print(f'- [{finding["points"]}] {finding["title"]}')
        print("  " + finding["explanation"])

    print("\nLimitations:")
    for limitation in report["limitations"]:
        print("- " + limitation)


if __name__ == "__main__":
    main()
