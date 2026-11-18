from flask import Blueprint, render_template, request

from app.modules.dmarc_checker import (
    get_dmarc_record,
    parse_dmarc_record,
    evaluate_dmarc
)


dmarc_bp = Blueprint(
    "dmarc",
    __name__,
    url_prefix="/dmarc"
)


@dmarc_bp.route("/analyzer", methods=["GET", "POST"])
def analyzer():

    results = None
    error = None

    if request.method == "POST":

        domain = request.form.get("domain", "").strip()

        try:

            dns_result = get_dmarc_record(domain)

            results = {
                "domain": domain,
                "dns_status": dns_result["status"],
                "dns_message": dns_result["message"],
                "record": dns_result["record"],
                "policy": None,
                "evaluation": None
            }

            if dns_result["status"] == "FOUND":

                policy = parse_dmarc_record(
                    dns_result["record"]
                )

                results["policy"] = policy

                from_domain = request.form.get(
                    "from_domain", ""
                ).strip()

                spf_result = request.form.get(
                    "spf_result", "NONE"
                ).upper()

                spf_domain = request.form.get(
                    "spf_domain", ""
                ).strip()

                dkim_result = request.form.get(
                    "dkim_result", "NONE"
                ).upper()

                dkim_domain = request.form.get(
                    "dkim_domain", ""
                ).strip()

                if from_domain:

                    results["evaluation"] = evaluate_dmarc(
                        from_domain,
                        spf_result,
                        spf_domain,
                        dkim_result,
                        dkim_domain,
                        policy
                    )

        except ValueError as exc:

            error = str(exc)

    return render_template(
        "dmarc_analyzer.html",
        results=results,
        error=error
    )