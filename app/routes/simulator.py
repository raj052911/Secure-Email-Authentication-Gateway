from flask import Blueprint, render_template, request

from app.modules.security_analyzer import evaluate_email_security


simulator_bp = Blueprint(
    "simulator",
    __name__,
    url_prefix="/simulator"
)


@simulator_bp.route("/", methods=["GET", "POST"])
def index():

    results = None
    error = None

    if request.method == "POST":

        from_domain = request.form.get(
            "from_domain", ""
        ).strip()

        spf_domain = request.form.get(
            "spf_domain", ""
        ).strip()

        spf_result = request.form.get(
            "spf_result", "FAIL"
        )

        dkim_domain = request.form.get(
            "dkim_domain", ""
        ).strip()

        dkim_result = request.form.get(
            "dkim_result", "FAIL"
        )

        dmarc_policy = request.form.get(
            "dmarc_policy", "reject"
        )

        spf_alignment = request.form.get(
            "spf_alignment", "r"
        )

        dkim_alignment = request.form.get(
            "dkim_alignment", "r"
        )

        try:

            results = evaluate_email_security(
                from_domain=from_domain,
                spf_domain=spf_domain,
                spf_result=spf_result,
                dkim_domain=dkim_domain,
                dkim_result=dkim_result,
                dmarc_policy=dmarc_policy,
                spf_alignment=spf_alignment,
                dkim_alignment=dkim_alignment
            )

        except ValueError as exc:

            error = str(exc)

    return render_template(
        "spoofing_simulator.html",
        results=results,
        error=error
    )