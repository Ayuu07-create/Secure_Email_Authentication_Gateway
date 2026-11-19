from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


def parse_raw_email(raw_email: str):
    if not raw_email or not raw_email.strip():
        raise ValueError("Email content cannot be empty.")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(
        raw_email.encode("utf-8", errors="replace")
    )

    return {
        "from": message.get("From", ""),
        "to": message.get("To", ""),
        "subject": message.get("Subject", ""),
        "return_path": message.get("Return-Path", ""),
        "date": message.get("Date", ""),
        "authentication_results": message.get_all(
            "Authentication-Results", []
        ),
        "received_spf": message.get_all(
            "Received-SPF", []
        ),
        "dkim_signature": message.get_all(
            "DKIM-Signature", []
        ),
    }


def extract_domain(address: str):
    _, email_address = parseaddr(address)

    if "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower().strip()


def parse_authentication_results(headers):
    results = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
    }

    authentication_headers = headers.get(
        "authentication_results",
        []
    )

    combined = " ".join(
        authentication_headers
    ).lower()

    for protocol in results:

        marker = f"{protocol}="

        if marker not in combined:
            continue

        value = (
            combined
            .split(marker, 1)[1]
            .split()[0]
            .strip(";")
        )

        results[protocol] = value

    return results
