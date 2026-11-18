from flask import Blueprint, render_template, request

from app.modules.dkim_generator import generate_dkim_keys
from app.modules.dkim_verifier import verify_dkim_signature


dkim_bp = Blueprint("dkim", __name__, url_prefix="/dkim")


# ==========================================
# DKIM KEY GENERATOR
# ==========================================

@dkim_bp.route("/manager", methods=["GET", "POST"])
def manager():

    results = None
    error = None

    if request.method == "POST":

        domain = request.form.get("domain", "").strip()
        selector = request.form.get("selector", "").strip()

        try:

            results = generate_dkim_keys(domain, selector)

        except (ValueError, FileExistsError, OSError) as exc:

            error = str(exc)

    return render_template(
        "dkim_manager.html",
        results=results,
        error=error
    )


# ==========================================
# DKIM SIGNATURE VERIFIER
# ==========================================

@dkim_bp.route("/verifier", methods=["GET", "POST"])
def verifier():

    results = None
    error = None

    if request.method == "POST":

        uploaded_file = request.files.get("email_file")

        try:

            if not uploaded_file or not uploaded_file.filename:

                raise ValueError("Please upload an .eml file.")

            if not uploaded_file.filename.lower().endswith(".eml"):

                raise ValueError("Only .eml files are supported.")

            raw_email = uploaded_file.read()

            if not raw_email:

                raise ValueError("The uploaded file is empty.")

            if len(raw_email) > 5 * 1024 * 1024:

                raise ValueError("Maximum file size is 5 MB.")

            results = verify_dkim_signature(raw_email)

        except (ValueError, OSError) as exc:

            error = str(exc)

    return render_template(
        "dkim_verifier.html",
        results=results,
        error=error
    )