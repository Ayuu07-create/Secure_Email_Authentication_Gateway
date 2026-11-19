from flask import Flask, render_template, request

from auth.parser import (
    parse_raw_email,
    extract_domain,
    parse_authentication_results
)

from auth.spf import analyze_spf
from auth.dkim import analyze_dkim
from auth.dmarc import analyze_dmarc


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None
    raw_email = ""

    if request.method == "POST":

        raw_email = request.form.get(
            "raw_email",
            ""
        )

        try:

            headers = parse_raw_email(
                raw_email
            )

            from_domain = extract_domain(
                headers.get("from", "")
            )

            authentication = (
                parse_authentication_results(
                    headers
                )
            )

            spf = None
            dkim = None
            dmarc = None

            if from_domain:

                spf = analyze_spf(
                    from_domain
                )

                dmarc = analyze_dmarc(
                    from_domain
                )

            if headers["dkim_signature"]:

                dkim = analyze_dkim(
                    headers["dkim_signature"][0]
                )

            result = {
                "headers": headers,
                "domain": from_domain,
                "authentication": authentication,
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
            }

        except Exception as exc:

            error = str(exc)

    return render_template(
        "index.html",
        result=result,
        error=error,
        raw_email=raw_email
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
