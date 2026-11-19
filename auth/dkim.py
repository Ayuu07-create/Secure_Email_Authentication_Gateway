import dns.resolver


def parse_dkim_signature(signature: str):

    result = {
        "domain": "",
        "selector": "",
        "algorithm": "",
        "canonicalization": "",
    }

    for part in signature.replace(
        "\n",
        " "
    ).split(";"):

        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split(
            "=",
            1
        )

        key = key.strip()
        value = value.strip()

        if key == "d":
            result["domain"] = value

        elif key == "s":
            result["selector"] = value

        elif key == "a":
            result["algorithm"] = value

        elif key == "c":
            result["canonicalization"] = value

    return result


def lookup_dkim_public_key(
    domain: str,
    selector: str
):

    if not domain or not selector:

        return {
            "status": "invalid",
            "record": None
        }

    hostname = (
        f"{selector}._domainkey.{domain}"
    )

    try:

        answers = dns.resolver.resolve(
            hostname,
            "TXT"
        )

        records = []

        for answer in answers:

            records.append(
                answer.to_text().strip('"')
            )

        return {
            "status": "found",
            "hostname": hostname,
            "record": " ".join(records)
        }

    except Exception as exc:

        return {
            "status": "not_found",
            "hostname": hostname,
            "record": None,
            "error": str(exc)
        }


def analyze_dkim(signature: str):

    parsed = parse_dkim_signature(
        signature
    )

    dns_result = lookup_dkim_public_key(
        parsed["domain"],
        parsed["selector"]
    )

    return {
        **parsed,
        "dns": dns_result
    }
