import dns.resolver


def get_dmarc_record(domain: str):

    hostname = f"_dmarc.{domain}"

    try:

        answers = dns.resolver.resolve(
            hostname,
            "TXT"
        )

        records = []

        for answer in answers:

            value = answer.to_text().strip('"')

            if value.lower().startswith("v=dmarc1"):
                records.append(value)

        if not records:
            return {
                "status": "not_found",
                "record": None
            }

        return {
            "status": "found",
            "record": records[0]
        }

    except Exception as exc:

        return {
            "status": "error",
            "record": None,
            "error": str(exc)
        }


def parse_dmarc_record(record: str):

    result = {}

    if not record:
        return result

    for part in record.split(";"):

        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        result[key.strip()] = value.strip()

    return result


def analyze_dmarc(domain: str):

    dns_result = get_dmarc_record(domain)

    if dns_result["status"] != "found":
        return dns_result

    parsed = parse_dmarc_record(
        dns_result["record"]
    )

    return {
        "status": "configured",
        "record": dns_result["record"],
        "policy": parsed.get("p", "unknown"),
        "subdomain_policy": parsed.get(
            "sp",
            "not specified"
        ),
        "dkim_alignment": parsed.get(
            "adkim",
            "relaxed"
        ),
        "spf_alignment": parsed.get(
            "aspf",
            "relaxed"
        ),
    }
