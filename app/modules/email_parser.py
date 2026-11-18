from email import policy
from email.parser import BytesParser


def parse_email(raw_email):
    """
    Parse raw email bytes and extract important email headers.
    """

    if not raw_email:
        raise ValueError("Email content cannot be empty.")

    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    extracted_data = {
        "from": str(message.get("From", "Not available")),
        "to": str(message.get("To", "Not available")),
        "subject": str(message.get("Subject", "Not available")),
        "date": str(message.get("Date", "Not available")),
        "return_path": str(message.get("Return-Path", "Not available")),
        "reply_to": str(message.get("Reply-To", "Not available")),
        "sender": str(message.get("Sender", "Not available")),
        "message_id": str(message.get("Message-ID", "Not available")),
        "received": [str(value) for value in message.get_all("Received", [])],
        "authentication_results": [
            str(value)
            for value in message.get_all("Authentication-Results", [])
        ],
        "dkim_signature": [
            str(value)
            for value in message.get_all("DKIM-Signature", [])
        ]
    }

    return extracted_data