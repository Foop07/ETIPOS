import pytest
import os
import sys

# Ensure protocols is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocols.crypto_engine import CryptoEngine, PayloadChunker


def test_x25519_key_exchange_and_derivation():
    # Node 1 (Sender)
    sender_priv, sender_pub = CryptoEngine.generate_x25519_keypair()
    sender_pub_b64 = CryptoEngine.public_key_to_b64(sender_pub)

    # Node 2 (Gateway)
    gateway_priv, gateway_pub = CryptoEngine.generate_x25519_keypair()
    gateway_pub_b64 = CryptoEngine.public_key_to_b64(gateway_pub)

    # Reconstruct public keys from b64 exchange
    sender_pub_reconstructed = CryptoEngine.b64_to_public_key(sender_pub_b64)
    gateway_pub_reconstructed = CryptoEngine.b64_to_public_key(gateway_pub_b64)

    # Derive keys
    sender_keys = CryptoEngine.derive_session_keys(sender_priv, gateway_pub_reconstructed)
    gateway_keys = CryptoEngine.derive_session_keys(gateway_priv, sender_pub_reconstructed)

    assert sender_keys["aes_key"] == gateway_keys["aes_key"]
    assert sender_keys["hmac_key"] == gateway_keys["hmac_key"]
    assert len(sender_keys["aes_key"]) == 32
    assert len(sender_keys["hmac_key"]) == 32


def test_aes_gcm_chunk_encryption_decryption():
    sender_priv, sender_pub = CryptoEngine.generate_x25519_keypair()
    gateway_priv, gateway_pub = CryptoEngine.generate_x25519_keypair()

    sender_keys = CryptoEngine.derive_session_keys(sender_priv, gateway_pub)
    gateway_keys = CryptoEngine.derive_session_keys(gateway_priv, sender_pub)

    plaintext = b"ETIPOS: Classified Secure Telemetry Data 0xDEADBEEF"
    ad = b"session_1234:chunk_0"

    encrypted_chunk = CryptoEngine.encrypt_chunk(
        plaintext, sender_keys["aes_key"], sender_keys["hmac_key"], associated_data=ad
    )

    decrypted = CryptoEngine.decrypt_chunk(
        encrypted_chunk, gateway_keys["aes_key"], gateway_keys["hmac_key"], associated_data=ad
    )

    assert decrypted == plaintext


def test_chunker_and_reassembly_multichunk():
    sender_priv, sender_pub = CryptoEngine.generate_x25519_keypair()
    gateway_priv, gateway_pub = CryptoEngine.generate_x25519_keypair()

    keys = CryptoEngine.derive_session_keys(sender_priv, gateway_pub)

    # 100 KB payload
    large_payload = os.urandom(100 * 1024)
    chunks = PayloadChunker.chunk_payload(
        large_payload,
        session_id="sess-abc",
        payload_id="payload-xyz",
        aes_key=keys["aes_key"],
        hmac_key=keys["hmac_key"],
        chunk_size=16 * 1024  # 16 KB chunks -> 7 chunks
    )

    assert len(chunks) == 7

    # Shuffle chunks to test out-of-order reassembly
    shuffled = [chunks[3], chunks[0], chunks[5], chunks[1], chunks[4], chunks[2], chunks[6]]
    reassembled = PayloadChunker.reassemble_payload(shuffled, keys["aes_key"], keys["hmac_key"])

    assert reassembled == large_payload


def test_ed25519_gateway_signature_verification():
    gw_priv, gw_pub = CryptoEngine.generate_ed25519_keypair()

    report = {
        "payload_id": "test-payload-001",
        "composite_risk_score": 1.5,
        "verdict": "PASS",
        "timestamp": 1788291000
    }

    sig = CryptoEngine.sign_audit_report(report, gw_priv)
    report["gateway_signature"] = sig

    assert CryptoEngine.verify_audit_report(report, gw_pub) is True

    # Tampering test
    report["composite_risk_score"] = 9.9
    assert CryptoEngine.verify_audit_report(report, gw_pub) is False


if __name__ == "__main__":
    pytest.main(["-v", __file__])

