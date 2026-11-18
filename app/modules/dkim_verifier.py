import re
from email import policy
from email.parser import BytesParser

import dkim
import dns.resolver


def extract_dkim_information(raw_email):
    """
    Extract and validate DKIM signature information.
    """

    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    signatures = message.get_all("DKIM-Signature", [])

    if not signatures:
        raise ValueError("No DKIM-Signature header found.")

    signature = str(signatures[0])

    tags = {}

    for item in signature.split(";"):
        if "=" in item:
            key, value = item.split("=", 1)
            tags[key.strip().lower()] = value.strip()

    domain = tags.get("d")
    selector = tags.get("s")
    algorithm = tags.get("a", "Not specified")

    if not domain or not selector:
        raise ValueError(
            "DKIM signature is missing the domain or selector."
        )

    # Normalize domain
    domain = domain.lower().rstrip(".")

    # Validate domain
    labels = domain.split(".")

    if (
        len(domain) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
            for label in labels
        )
        or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
    ):
        raise ValueError("Invalid DKIM signing domain.")

    # Validate selector
    if not re.fullmatch(r"[A-Za-z0-9_-]+", selector):
        raise ValueError("Invalid DKIM selector.")

    return {
        "domain": domain,
        "selector": selector,
        "algorithm": algorithm,
        "dns_name": f"{selector}._domainkey.{domain}"
    }


def dns_lookup(name, timeout=5):
    """
    Retrieve a DKIM public key TXT record from DNS.

    This function is supplied to dkimpy during verification.
    """

    if isinstance(name, bytes):
        name = name.decode("ascii")

    try:

        answers = dns.resolver.resolve(
            name,
            "TXT",
            lifetime=timeout
        )

        records = []

        for answer in answers:

            record = b"".join(answer.strings)

            if b"p=" in record:
                records.append(record)

        if not records:
            return None

        if len(records) > 1:
            raise ValueError(
                "Multiple possible DKIM key records were returned."
            )

        return records[0]

    except dns.resolver.NXDOMAIN:
        return None

    except dns.resolver.NoAnswer:
        return None


def verify_dkim_signature(raw_email):
    """
    Perform actual DKIM cryptographic verification.
    """

    if not raw_email:
        raise ValueError("Email content cannot be empty.")

    # Extract signature information

    information = extract_dkim_information(raw_email)

    # Retrieve DNS public key and verify signature

    verifier = dkim.DKIM(raw_email)

    try:

        verification_result = verifier.verify(
            idx=0,
            dnsfunc=dns_lookup
        )

        if verification_result:

            status = "PASS"

            explanation = (
                "DKIM cryptographic signature verified successfully."
            )

        else:

            status = "FAIL"

            explanation = (
                "DKIM signature verification failed. "
                "The signature, email content or public key may be invalid."
            )

    except Exception as exc:

        status = "ERROR"

        explanation = str(exc)

    return {
        "status": status,
        "domain": information["domain"],
        "selector": information["selector"],
        "algorithm": information["algorithm"],
        "dns_name": information["dns_name"],
        "explanation": explanation
    }
def get_dkim_report_data(raw_email):
    """
    Collect DKIM verification information for PDF reporting.
    """

    result = verify_dkim_signature(raw_email)

    findings = []
    recommendations = []

    if result["status"] == "PASS":

        findings.append(
            "DKIM cryptographic signature verified successfully."
        )

        findings.append(
            f"DKIM signing domain: {result['domain']}."
        )

        findings.append(
            f"DKIM selector: {result['selector']}."
        )

        recommendations.append(
            "Continue protecting the DKIM private key."
        )

        recommendations.append(
            "Monitor DKIM verification results regularly."
        )

    elif result["status"] == "FAIL":

        findings.append(
            "DKIM signature verification failed."
        )

        recommendations.append(
            "Check the email signature and corresponding public key."
        )

    else:

        findings.append(
            f"DKIM verification error: {result['explanation']}"
        )

        recommendations.append(
            "Investigate the DKIM signature and DNS public-key configuration."
        )

    return {
        "dkim_status": result["status"],
        "dkim_domain": result["domain"],
        "dkim_selector": result["selector"],
        "dkim_algorithm": result["algorithm"],
        "dkim_dns_name": result["dns_name"],
        "dkim_message": result["explanation"],
        "findings": findings,
        "recommendations": recommendations
    }