"""DKIM signature verification on real (test-signed) messages."""
from __future__ import annotations

import base64

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.app.services.email_identity.dkim_verify import verify_message
from backend.app.services.email_identity.dns_client import StaticDnsClient


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, base64.b64encode(pub).decode()


MSG = (b"From: Alerts <alerts@signed.example>\r\nTo: soc@acme.example\r\nSubject: Test\r\n"
       b"Date: Sat, 07 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@signed.example>\r\n\r\nHello from Sentrix tests.\r\n")


def _signed():
    priv, pub = _keypair()
    sig = dkim.sign(MSG, b"s2026", b"signed.example", priv, include_headers=[b"from", b"to", b"subject", b"date"])
    dns = StaticDnsClient({("s2026._domainkey.signed.example", "TXT"): [f"v=DKIM1; k=rsa; p={pub}"]})
    return sig + MSG, dns


def test_valid_signature_passes_and_aligns():
    raw, dns = _signed()
    r = verify_message(raw, dns)
    assert r.status == "signature_pass"
    assert r.signatures[0].verified and r.signatures[0].aligned_with_from
    assert "does not identify the human sender" in r.explanation


def test_tampered_body_fails():
    raw, dns = _signed()
    r = verify_message(raw.replace(b"Hello", b"Pay now"), dns)
    assert r.status == "signature_fail"


def test_unsigned_message_has_no_signature_even_with_receiver_claims():
    raw = b"Authentication-Results: mx.example; dkim=pass header.d=signed.example\r\n" + MSG
    r = verify_message(raw, StaticDnsClient({}))
    assert r.status == "no_signature"
    assert r.receiver_claims  # reported, but never treated as proof
