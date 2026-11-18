import re

import dns.resolver
import dns.exception

from publicsuffix2 import get_sld


def validate_domain(domain):
    """Validate and normalize a domain name."""

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        raise ValueError("Please enter a valid domain name.")

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("Please enter a valid domain name.")

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


def get_dmarc_record(domain):
    """
    Retrieve the DMARC TXT record from DNS.
    """

    domain = validate_domain(domain)

    dns_name = f"_dmarc.{domain}"

    try:

        answers = dns.resolver.resolve(
            dns_name,
            "TXT",
            lifetime=5
        )

        records = []

        for answer in answers:

            record = b"".join(answer.strings).decode(
                "utf-8",
                errors="replace"
            )

            if record.lower().startswith("v=dmarc1"):
                records.append(record)

        if not records:

            return {
                "status": "NONE",
                "record": None,
                "message": "No DMARC record found."
            }

        if len(records) > 1:

            return {
                "status": "PERMERROR",
                "record": records,
                "message": "Multiple DMARC records found."
            }

        return {
            "status": "FOUND",
            "record": records[0],
            "message": "DMARC record successfully retrieved."
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
            "message": "No DMARC TXT record found."
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


def parse_dmarc_record(record):
    """
    Parse DMARC tags and validate important policy fields.
    """

    if not record:
        raise ValueError("DMARC record is empty.")

    parts = [part.strip() for part in record.split(";")]

    tags = {}

    for part in parts:

        if not part:
            continue

        if "=" not in part:
            raise ValueError(f"Invalid DMARC tag: {part}")

        key, value = part.split("=", 1)

        key = key.strip().lower()
        value = value.strip()

        if key in tags:
            raise ValueError(f"Duplicate DMARC tag: {key}")

        tags[key] = value

    if tags.get("v", "").upper() != "DMARC1":
        raise ValueError("Invalid DMARC version.")

    policy = tags.get("p", "").lower()

    if policy not in ("none", "quarantine", "reject"):
        raise ValueError("Invalid or missing DMARC policy.")

    aspf = tags.get("aspf", "r").lower()
    adkim = tags.get("adkim", "r").lower()

    if aspf not in ("r", "s"):
        raise ValueError("Invalid SPF alignment mode.")

    if adkim not in ("r", "s"):
        raise ValueError("Invalid DKIM alignment mode.")

    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        raise ValueError("Invalid DMARC percentage.")

    if not 0 <= pct <= 100:
        raise ValueError("DMARC percentage must be between 0 and 100.")

    return {
        "version": tags.get("v"),
        "policy": policy,
        "subdomain_policy": tags.get("sp", "Not specified"),
        "spf_alignment": aspf,
        "dkim_alignment": adkim,
        "aggregate_reports": tags.get("rua", "Not configured"),
        "forensic_reports": tags.get("ruf", "Not configured"),
        "percentage": pct
    }


def domains_aligned(domain1, domain2, mode):
    """
    Check strict or relaxed domain alignment.
    """

    domain1 = validate_domain(domain1)
    domain2 = validate_domain(domain2)

    if mode == "s":
        return domain1 == domain2

    organizational_domain1 = get_sld(domain1)
    organizational_domain2 = get_sld(domain2)

    if not organizational_domain1 or not organizational_domain2:
        return False

    return organizational_domain1 == organizational_domain2


def evaluate_dmarc(
    from_domain,
    spf_result,
    spf_domain,
    dkim_result,
    dkim_domain,
    dmarc_policy
):
    """
    Evaluate DMARC using supplied SPF and DKIM results.

    SPF and DKIM results must come from actual authentication checks.
    """

    from_domain = validate_domain(from_domain)

    spf_aligned = False
    dkim_aligned = False

    if spf_result.upper() == "PASS" and spf_domain:

        spf_aligned = domains_aligned(
            from_domain,
            spf_domain,
            dmarc_policy["spf_alignment"]
        )

    if dkim_result.upper() == "PASS" and dkim_domain:

        dkim_aligned = domains_aligned(
            from_domain,
            dkim_domain,
            dmarc_policy["dkim_alignment"]
        )

    dmarc_pass = spf_aligned or dkim_aligned

    return {
        "status": "PASS" if dmarc_pass else "FAIL",
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "explanation": (
            "DMARC passed because at least one authenticated "
            "identifier passed alignment."
            if dmarc_pass
            else
            "DMARC failed because neither SPF nor DKIM "
            "provided an authenticated aligned identifier."
        )
    }


def get_dmarc_report_data(domain):
    """
    Collect DMARC DNS information for PDF report generation.

    This function checks the published DNS record.
    It does not verify an individual email's DMARC authentication.
    """

    result = get_dmarc_record(domain)

    record = result.get("record")

    findings = []
    recommendations = []

    policy = "Not available"
    parsed_data = {}

    if result["status"] == "FOUND":

        try:

            parsed_data = parse_dmarc_record(record)

            policy = parsed_data["policy"]

            findings.append(
                f"DMARC DNS record is published for {domain}."
            )

            findings.append(
                f"DMARC policy is configured as {policy}."
            )

            findings.append(
                f"SPF alignment mode: {parsed_data['spf_alignment']}."
            )

            findings.append(
                f"DKIM alignment mode: {parsed_data['dkim_alignment']}."
            )

            findings.append(
                f"DMARC policy percentage: {parsed_data['percentage']}%."
            )

            if parsed_data["aggregate_reports"] == "Not configured":

                recommendations.append(
                    "Consider configuring a DMARC aggregate reporting address."
                )

            else:

                findings.append(
                    "DMARC aggregate reporting is configured."
                )

            recommendations.append(
                "Monitor DMARC aggregate reports regularly."
            )

            recommendations.append(
                "Verify SPF and DKIM alignment with the visible From domain."
            )

        except ValueError as exc:

            findings.append(
                f"DMARC record validation issue: {exc}"
            )

            recommendations.append(
                "Review and correct the DMARC DNS record."
            )

    elif result["status"] == "NONE":

        findings.append(
            f"No DMARC DNS record was found for {domain}."
        )

        recommendations.append(
            "Publish a valid DMARC DNS record."
        )

    else:

        findings.append(result["message"])

        recommendations.append(
            "Investigate the DMARC DNS lookup problem."
        )

    return {
        "dmarc_status": result["status"],
        "dmarc_record": (
            record if isinstance(record, str) else "Not available"
        ),
        "dmarc_policy": policy,
        "dmarc_details": parsed_data,
        "dmarc_message": result["message"],
        "findings": findings,
        "recommendations": recommendations
    }