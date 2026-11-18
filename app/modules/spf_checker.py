import ipaddress
import re

import dns.resolver
import dns.exception
import spf


def validate_domain(domain):
    """Validate and normalize a domain name."""

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        raise ValueError("Please enter a valid domain name.")

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("Invalid domain format.")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            raise ValueError("Invalid domain format.")

    if not re.fullmatch(r"[a-z]{2,63}", labels[-1]):
        raise ValueError("Invalid top-level domain.")

    return domain


def get_spf_record(domain):
    """Retrieve SPF TXT records from DNS."""

    domain = validate_domain(domain)

    try:
        answers = dns.resolver.resolve(
            domain,
            "TXT",
            lifetime=5
        )

        txt_records = []

        for answer in answers:

            record = b"".join(answer.strings).decode(
                "utf-8",
                errors="replace"
            )

            if record.lower().startswith("v=spf1"):
                txt_records.append(record)

        if not txt_records:
            return {
                "status": "NONE",
                "record": None,
                "message": "No SPF record found."
            }

        if len(txt_records) > 1:
            return {
                "status": "PERMERROR",
                "record": txt_records,
                "message": "Multiple SPF records found. This is invalid."
            }

        return {
            "status": "FOUND",
            "record": txt_records[0],
            "message": "SPF record successfully retrieved."
        }

    except dns.resolver.NXDOMAIN:
        return {
            "status": "NXDOMAIN",
            "record": None,
            "message": "The domain does not exist."
        }

    except dns.resolver.NoAnswer:
        return {
            "status": "NONE",
            "record": None,
            "message": "No TXT records found."
        }

    except dns.exception.Timeout:
        return {
            "status": "TEMPERROR",
            "record": None,
            "message": "DNS lookup timed out."
        }

    except dns.exception.DNSException as exc:
        return {
            "status": "TEMPERROR",
            "record": None,
            "message": f"DNS lookup failed: {exc}"
        }


def extract_spf_mechanisms(record):
    """Extract SPF mechanisms and modifiers."""

    if not record:
        return []

    parts = record.split()

    return parts[1:] if len(parts) > 1 else []


def evaluate_spf(domain, sender_ip, sender_email, helo=None):
    """
    Evaluate an IP address against the domain's SPF policy.

    Requires a real sending IP and envelope sender address.
    """

    domain = validate_domain(domain)

    try:
        ipaddress.ip_address(sender_ip)
    except ValueError:
        raise ValueError("Please enter a valid IPv4 or IPv6 address.")

    sender_email = sender_email.strip()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+", sender_email):
        raise ValueError("Please enter a valid sender email address.")

    sender_domain = sender_email.rsplit("@", 1)[1].lower().rstrip(".")

    if sender_domain != domain:
        raise ValueError(
            "The sender email domain must match the domain being analyzed."
        )

    try:
        result = spf.check2(
            i=sender_ip,
            s=sender_email,
            h=helo.strip() if helo else domain
        )

        return {
            "status": result[0].upper(),
            "explanation": result[1]
        }

    except Exception as exc:
        return {
            "status": "ERROR",
            "explanation": str(exc)
        }


def get_spf_report_data(domain):
    """
    Collect SPF DNS information for PDF report generation.

    This checks the published DNS record.
    It does not perform sender IP authentication.
    """

    result = get_spf_record(domain)

    record = result.get("record")

    mechanisms = extract_spf_mechanisms(
        record if isinstance(record, str) else None
    )

    findings = []
    recommendations = []

    if result["status"] == "FOUND":

        findings.append(
            f"SPF DNS record is published for {domain}."
        )

        findings.append(
            f"SPF mechanisms detected: {', '.join(mechanisms)}"
        )

        if "~all" in mechanisms:
            findings.append(
                "SPF record uses the soft-fail qualifier (~all)."
            )

            recommendations.append(
                "Review whether the SPF soft-fail policy is appropriate."
            )

        elif "-all" in mechanisms:
            findings.append(
                "SPF record uses the hard-fail qualifier (-all)."
            )

        elif "?all" in mechanisms:
            findings.append(
                "SPF record uses the neutral qualifier (?all)."
            )

            recommendations.append(
                "Review the SPF neutral policy and consider an appropriate enforcement policy."
            )

        else:
            recommendations.append(
                "Review the SPF record's final mechanism and policy."
            )

        recommendations.append(
            "Verify that all authorized email-sending services are included in the SPF record."
        )

    elif result["status"] == "NONE":

        findings.append(
            f"No SPF DNS record was found for {domain}."
        )

        recommendations.append(
            "Publish a valid SPF DNS record for the domain."
        )

    else:

        findings.append(result["message"])

        recommendations.append(
            "Investigate the SPF DNS lookup problem and check the domain configuration."
        )

    return {
        "spf_status": result["status"],
        "spf_record": record if isinstance(record, str) else "Not available",
        "spf_mechanisms": mechanisms,
        "spf_message": result["message"],
        "findings": findings,
        "recommendations": recommendations
    }