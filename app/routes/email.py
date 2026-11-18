from flask import (
    Blueprint,
    render_template,
    request
)

from app.modules.email_parser import parse_email


email_bp = Blueprint("email", __name__, url_prefix="/email")


@email_bp.route("/analyzer", methods=["GET", "POST"])
def analyzer():

    results = None
    error = None

    if request.method == "POST":

        raw_email = None

        uploaded_file = request.files.get("email_file")
        pasted_email = request.form.get("raw_email", "").strip()

        try:

            if uploaded_file and uploaded_file.filename:

                if not uploaded_file.filename.lower().endswith(".eml"):
                    raise ValueError("Please upload a valid .eml file.")

                raw_email = uploaded_file.read()

                if len(raw_email) > 5 * 1024 * 1024:
                    raise ValueError("File size must not exceed 5 MB.")

            elif pasted_email:

                raw_email = pasted_email.encode("utf-8")

            else:

                raise ValueError(
                    "Please upload an email file or paste email content."
                )

            results = parse_email(raw_email)

        except (ValueError, Exception) as exc:

            error = str(exc)

    return render_template(
        "email_analyzer.html",
        results=results,
        error=error
    )