import base64
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


KEYS_DIRECTORY = Path(__file__).resolve().parents[2] / "keys"


def validate_domain(domain):

    domain = domain.strip().lower()

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    if not re.fullmatch(pattern, domain):
        raise ValueError("Please enter a valid domain name.")

    return domain


def validate_selector(selector):

    selector = selector.strip()

    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", selector):
        raise ValueError("Invalid DKIM selector.")

    return selector


def generate_dkim_keys(domain, selector):

    domain = validate_domain(domain)
    selector = validate_selector(selector)

    KEYS_DIRECTORY.mkdir(parents=True, exist_ok=True)

    private_key_path = KEYS_DIRECTORY / f"{domain}_{selector}_private.pem"

    if private_key_path.exists():
        raise FileExistsError(
            "A key with this domain and selector already exists. "
            "Choose another selector to avoid overwriting the existing key."
        )

    # Generate RSA private key

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Export private key in PEM format

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save private key locally

    with open(private_key_path, "xb") as file:
        file.write(private_pem)

    # Generate public key

    public_key = private_key.public_key()

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_base64 = base64.b64encode(public_der).decode("ascii")

    dns_name = f"{selector}._domainkey.{domain}"

    dns_value = f"v=DKIM1; k=rsa; p={public_key_base64}"

    return {
        "domain": domain,
        "selector": selector,
        "dns_name": dns_name,
        "dns_value": dns_value,
        "private_key_path": str(private_key_path),
        "key_size": 2048,
        "status": "SUCCESS"
    }