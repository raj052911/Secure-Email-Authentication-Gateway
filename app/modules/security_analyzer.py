from app.modules.dmarc_checker import (
    validate_domain,
    domains_aligned
)


VALID_RESULTS = {"PASS", "FAIL", "NONE"}
VALID_POLICIES = {"none", "quarantine", "reject"}
VALID_ALIGNMENT = {"r", "s"}


def evaluate_email_security(
    from_domain,
    spf_domain,
    spf_result,
    dkim_domain,
    dkim_result,
    dmarc_policy,
    spf_alignment="r",
    dkim_alignment="r"
):
    """
    Simulate SPF, DKIM and DMARC authentication outcomes.

    This is a controlled simulation, not a real email
    authentication or mail-server enforcement process.
    """

    from_domain = validate_domain(from_domain)

    spf_result = spf_result.upper()
    dkim_result = dkim_result.upper()
    dmarc_policy = dmarc_policy.lower()

    if spf_result not in VALID_RESULTS:
        raise ValueError("Invalid SPF authentication result.")

    if dkim_result not in VALID_RESULTS:
        raise ValueError("Invalid DKIM authentication result.")

    if dmarc_policy not in VALID_POLICIES:
        raise ValueError("Invalid DMARC policy.")

    if spf_alignment not in VALID_ALIGNMENT:
        raise ValueError("Invalid SPF alignment mode.")

    if dkim_alignment not in VALID_ALIGNMENT:
        raise ValueError("Invalid DKIM alignment mode.")

    # SPF alignment

    spf_aligned = False

    if spf_result == "PASS" and spf_domain.strip():

        spf_domain = validate_domain(spf_domain)

        spf_aligned = domains_aligned(
            from_domain,
            spf_domain,
            spf_alignment
        )

    # DKIM alignment

    dkim_aligned = False

    if dkim_result == "PASS" and dkim_domain.strip():

        dkim_domain = validate_domain(dkim_domain)

        dkim_aligned = domains_aligned(
            from_domain,
            dkim_domain,
            dkim_alignment
        )

    # DMARC passes if at least one authenticated
    # identifier is aligned with the visible From domain.

    dmarc_pass = spf_aligned or dkim_aligned

    if dmarc_pass:

        dmarc_status = "PASS"
        handling = "ACCEPT"

        explanation = (
            "DMARC passed because at least one authenticated "
            "identifier passed domain alignment."
        )

    else:

        dmarc_status = "FAIL"

        if dmarc_policy == "none":
            handling = "MONITOR"

        elif dmarc_policy == "quarantine":
            handling = "QUARANTINE"

        else:
            handling = "REJECT"

        explanation = (
            "DMARC failed because neither SPF nor DKIM "
            "provided an authenticated aligned identifier."
        )

    return {
        "from_domain": from_domain,

        "spf_result": spf_result,
        "spf_domain": spf_domain if spf_result == "PASS" else "Not applicable",
        "spf_aligned": spf_aligned,

        "dkim_result": dkim_result,
        "dkim_domain": dkim_domain if dkim_result == "PASS" else "Not applicable",
        "dkim_aligned": dkim_aligned,

        "dmarc_status": dmarc_status,
        "dmarc_policy": dmarc_policy,
        "handling": handling,
        "explanation": explanation
    }