from flask import Blueprint, render_template, request

from app.modules.spf_checker import (
    get_spf_record,
    extract_spf_mechanisms,
    evaluate_spf
)


spf_bp = Blueprint("spf", __name__, url_prefix="/spf")


@spf_bp.route("/analyzer", methods=["GET", "POST"])
def analyzer():

    results = None
    error = None

    if request.method == "POST":

        domain = request.form.get("domain", "").strip()

        sender_ip = request.form.get("sender_ip", "").strip()

        sender_email = request.form.get("sender_email", "").strip()

        helo = request.form.get("helo", "").strip()

        try:

            # Retrieve SPF DNS record

            dns_result = get_spf_record(domain)

            results = {
                "domain": domain,
                "dns_status": dns_result["status"],
                "record": dns_result["record"],
                "dns_message": dns_result["message"],
                "mechanisms": [],
                "evaluation": None,
                "explanation": None
            }

            # Extract mechanisms

            if dns_result["status"] == "FOUND":

                results["mechanisms"] = extract_spf_mechanisms(
                    dns_result["record"]
                )

            # Perform SPF evaluation only if a valid SPF record exists

            if sender_ip and sender_email:

                if dns_result["status"] == "FOUND":

                    evaluation = evaluate_spf(
                        domain,
                        sender_ip,
                        sender_email,
                        helo
                    )

                    results["evaluation"] = evaluation["status"]

                    results["explanation"] = evaluation["explanation"]

                else:

                    results["evaluation"] = "NOT EVALUATED"

                    results["explanation"] = (
                        "SPF evaluation was not performed because "
                        "a single valid SPF record was not found."
                    )

        except ValueError as exc:

            error = str(exc)

    return render_template(
        "spf_analyzer.html",
        results=results,
        error=error
    )