import os
from datetime import datetime

from flask import (
    Blueprint,
    render_template,
    request,
    send_file,
    flash,
    redirect,
    url_for
)

from app.modules.report_generator import generate_security_report
from app.modules.spf_checker import get_spf_report_data
from app.modules.dmarc_checker import get_dmarc_report_data
from app.modules.dkim_verifier import get_dkim_report_data

reports_bp = Blueprint("reports", __name__)

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

REPORT_FOLDER = os.path.join(BASE_DIR, "reports")


def clean_text_list(value):
    return [
        line.strip()
        for line in value.splitlines()
        if line.strip()
    ]


def generate_pdf(report_data):
    os.makedirs(REPORT_FOLDER, exist_ok=True)

    filename = (
        "email_security_report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".pdf"
    )

    output_path = os.path.join(REPORT_FOLDER, filename)

    generate_security_report(report_data, output_path)

    return send_file(
        output_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


@reports_bp.route("/", methods=["GET"])
def index():
    return render_template("reports.html")


@reports_bp.route("/download", methods=["POST"])
def download_report():
    """Generate a report using manually entered information."""

    domain = request.form.get("domain", "").strip()

    if not domain:
        flash("Please enter a domain name.", "danger")
        return redirect(url_for("reports.index"))

    report_data = {
        "domain": domain,

        "spf_status": request.form.get("spf_status", "Not analyzed"),
        "spf_record": request.form.get("spf_record", "").strip()
                      or "Not available",

        "dkim_status": request.form.get("dkim_status", "Not analyzed"),
        "dkim_domain": request.form.get("dkim_domain", "").strip()
                       or "Not available",
        "dkim_selector": request.form.get("dkim_selector", "").strip()
                         or "Not available",

        "dmarc_status": request.form.get("dmarc_status", "Not analyzed"),
        "dmarc_record": request.form.get("dmarc_record", "").strip()
                        or "Not available",
        "dmarc_policy": request.form.get("dmarc_policy", "Not available"),

        "findings": clean_text_list(
            request.form.get("findings", "")
        ),

        "recommendations": clean_text_list(
            request.form.get("recommendations", "")
        )
    }

    try:
        return generate_pdf(report_data)

    except Exception:
        flash("Unable to generate the PDF report.", "danger")
        return redirect(url_for("reports.index"))


@reports_bp.route("/automatic-download", methods=["POST"])
def automatic_download():
    """Generate a report using actual DNS and DKIM analysis."""

    domain = request.form.get("domain", "").strip()

    if not domain:
        flash("Please enter a domain name.", "danger")
        return redirect(url_for("reports.index"))

    uploaded_email = request.files.get("email_file")

    findings = []
    recommendations = []

    try:
        # SPF DNS analysis
        spf_data = get_spf_report_data(domain)

        findings.extend(spf_data["findings"])
        recommendations.extend(spf_data["recommendations"])

        # DMARC DNS analysis
        dmarc_data = get_dmarc_report_data(domain)

        findings.extend(dmarc_data["findings"])
        recommendations.extend(dmarc_data["recommendations"])

        # DKIM verification
        if uploaded_email and uploaded_email.filename:

            raw_email = uploaded_email.read()

            if not raw_email:
                raise ValueError("Uploaded email file is empty.")

            dkim_data = get_dkim_report_data(raw_email)

            findings.extend(dkim_data["findings"])
            recommendations.extend(dkim_data["recommendations"])

        else:
            dkim_data = {
                "dkim_status": "NOT TESTED",
                "dkim_domain": "Not available",
                "dkim_selector": "Not available"
            }

            findings.append(
                "DKIM verification was not performed because no signed email was uploaded."
            )

            recommendations.append(
                "Upload an original signed .eml email to perform DKIM verification."
            )

        # Combine all analyzer results
        report_data = {
            "domain": domain,

            "spf_status": spf_data["spf_status"],
            "spf_record": spf_data["spf_record"],

            "dkim_status": dkim_data["dkim_status"],
            "dkim_domain": dkim_data["dkim_domain"],
            "dkim_selector": dkim_data["dkim_selector"],

            "dmarc_status": dmarc_data["dmarc_status"],
            "dmarc_record": dmarc_data["dmarc_record"],
            "dmarc_policy": dmarc_data["dmarc_policy"],

            "findings": findings,
            "recommendations": recommendations
        }

        return generate_pdf(report_data)

    except (ValueError, OSError) as exc:
        flash(str(exc), "danger")
        return redirect(url_for("reports.index"))

    except Exception:
        flash(
            "Automatic report generation failed. Check the server terminal for details.",
            "danger"
        )
        raise