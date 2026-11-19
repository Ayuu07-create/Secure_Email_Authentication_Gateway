import dns.resolver


def get_spf_record(domain: str):

    try:

        answers = dns.resolver.resolve(
            domain,
            "TXT"
        )

        records = []

        for answer in answers:

            value = answer.to_text().strip('"')

            if value.lower().startswith("v=spf1"):
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


def analyze_spf(domain: str):

    if not domain:
        return {
            "status": "invalid_domain"
        }

    return get_spf_record(domain)
