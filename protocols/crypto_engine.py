"""
ETIPOS Cryptographic Engine (X25519, AES-256-GCM, HMAC-SHA256, Ed25519)
Implements:
  - Bernstein (2006) RFC 7748: Curve25519 / X25519 Ephemeral Diffie-Hellman Key Agreement
  - Rogaway (2002) NIST SP 800-38D: Authenticated Encryption with Associated Data (AEAD) AES-GCM
  - RFC 5869: HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
  - RFC 8032: Ed25519 Digital Signatures for Gateway Audit Verification
"""

import os
import json
import base64
import hashlib
import hmac
from typing import Tuple, Dict, Any, List
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption
)


class CryptoEngine:
    """Core cryptographic engine for ETIPOS nodes."""

    @staticmethod
    def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
        """Generates an ephemeral X25519 private-public key pair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def public_key_to_b64(public_key: x25519.X25519PublicKey) -> str:
        """Serializes X25519 public key to raw base64 string."""
        raw_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        return base64.b64encode(raw_bytes).decode('utf-8')

    @staticmethod
    def b64_to_public_key(b64_str: str) -> x25519.X25519PublicKey:
        """Deserializes base64 string to X25519 public key."""
        raw_bytes = base64.b64decode(b64_str)
        return x25519.X25519PublicKey.from_public_bytes(raw_bytes)

    @staticmethod
    def derive_session_keys(
        private_key: x25519.X25519PrivateKey,
        peer_public_key: x25519.X25519PublicKey,
        salt: bytes = b"ETIPOS-v1.0-SALT",
        info: bytes = b"ETIPOS-SESSION-KEYS"
    ) -> Dict[str, bytes]:
        """
        Performs Diffie-Hellman and derives AES-256 encryption key + HMAC integrity key.
        Returns:
            {"aes_key": 32 bytes, "hmac_key": 32 bytes}
        """
        shared_secret = private_key.exchange(peer_public_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes AES + 32 bytes HMAC
            salt=salt,
            info=info,
        )
        key_material = hkdf.derive(shared_secret)
        return {
            "aes_key": key_material[:32],
            "hmac_key": key_material[32:]
        }

    @staticmethod
    def encrypt_chunk(
        plaintext: bytes,
        aes_key: bytes,
        hmac_key: bytes,
        associated_data: bytes = b""
    ) -> Dict[str, str]:
        """
        Encrypts a chunk with AES-256-GCM and calculates HMAC-SHA256.
        Returns dictionary with base64 encoded ciphertext, nonce, auth_tag, hmac.
        """
        nonce = os.urandom(12)  # 96-bit standard GCM nonce
        aesgcm = AESGCM(aes_key)
        
        # In cryptography library, AESGCM.encrypt returns ciphertext + tag appended (16 bytes tag at end)
        enc_result = aesgcm.encrypt(nonce, plaintext, associated_data)
        ciphertext = enc_result[:-16]
        auth_tag = enc_result[-16:]

        # Calculate HMAC over (nonce + ciphertext + auth_tag + associated_data)
        h = hmac.new(hmac_key, digestmod=hashlib.sha256)
        h.update(nonce)
        h.update(ciphertext)
        h.update(auth_tag)
        h.update(associated_data)
        hmac_tag = h.digest()

        return {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "auth_tag": base64.b64encode(auth_tag).decode('utf-8'),
            "hmac_sha256": base64.b64encode(hmac_tag).decode('utf-8')
        }

    @staticmethod
    def decrypt_chunk(
        chunk_dict: Dict[str, str],
        aes_key: bytes,
        hmac_key: bytes,
        associated_data: bytes = b""
    ) -> bytes:
        """
        Verifies HMAC and decrypts AES-256-GCM chunk.
        Raises ValueError if integrity or authentication fails.
        """
        nonce = base64.b64decode(chunk_dict["nonce"])
        ciphertext = base64.b64decode(chunk_dict["ciphertext"])
        auth_tag = base64.b64decode(chunk_dict["auth_tag"])
        expected_hmac = base64.b64decode(chunk_dict["hmac_sha256"])

        # 1. Verify HMAC
        h = hmac.new(hmac_key, digestmod=hashlib.sha256)
        h.update(nonce)
        h.update(ciphertext)
        h.update(auth_tag)
        h.update(associated_data)
        computed_hmac = h.digest()

        if not hmac.compare_digest(computed_hmac, expected_hmac):
            raise ValueError("HMAC verification failed: chunk tampering detected!")

        # 2. Decrypt AES-256-GCM
        aesgcm = AESGCM(aes_key)
        full_cipher_with_tag = ciphertext + auth_tag
        return aesgcm.decrypt(nonce, full_cipher_with_tag, associated_data)

    # -------------------------------------------------------------
    # Ed25519 Gateway Signing & Verification (Node 2 -> Node 3)
    # -------------------------------------------------------------
    @staticmethod
    def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generates Gateway Ed25519 signing keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def ed25519_public_key_to_b64(public_key: ed25519.Ed25519PublicKey) -> str:
        """Serializes Ed25519 public key to raw base64 string."""
        raw_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        return base64.b64encode(raw_bytes).decode('utf-8')

    @staticmethod
    def b64_to_ed25519_public_key(b64_str: str) -> ed25519.Ed25519PublicKey:
        """Deserializes base64 string to Ed25519 public key."""
        raw_bytes = base64.b64decode(b64_str)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)

    @staticmethod
    def sign_audit_report(report_data: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
        """Signs the canonical JSON of an inspection report with Ed25519."""
        # Clean copy without signature field
        data_to_sign = {k: v for k, v in report_data.items() if k != "gateway_signature"}
        canonical_bytes = json.dumps(data_to_sign, sort_keys=True).encode('utf-8')
        signature = private_key.sign(canonical_bytes)
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_audit_report(report_data: Dict[str, Any], public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verifies the Ed25519 signature on an inspection report."""
        if "gateway_signature" not in report_data:
            return False
        signature = base64.b64decode(report_data["gateway_signature"])
        data_to_verify = {k: v for k, v in report_data.items() if k != "gateway_signature"}
        canonical_bytes = json.dumps(data_to_verify, sort_keys=True).encode('utf-8')
        try:
            public_key.verify(signature, canonical_bytes)
            return True
        except Exception:
            return False


class PayloadChunker:
    """Splits raw payload bytes into secure ETIPOS authenticated frames."""

    DEFAULT_CHUNK_SIZE = 32 * 1024  # 32 KB

    @classmethod
    def chunk_payload(
        cls,
        payload_bytes: bytes,
        session_id: str,
        payload_id: str,
        aes_key: bytes,
        hmac_key: bytes,
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> List[Dict[str, Any]]:
        """Chunks and encrypts raw bytes into authenticated frames."""
        total_size = len(payload_bytes)
        chunks = []
        
        # Calculate number of chunks
        num_chunks = (total_size + chunk_size - 1) // chunk_size if total_size > 0 else 1
        
        for idx in range(num_chunks):
            start = idx * chunk_size
            end = min(start + chunk_size, total_size)
            slice_bytes = payload_bytes[start:end]
            
            # Associated data binds chunk index and session
            ad = f"{session_id}:{payload_id}:{idx}:{num_chunks}".encode('utf-8')
            enc_info = CryptoEngine.encrypt_chunk(slice_bytes, aes_key, hmac_key, ad)
            
            chunk_frame = {
                "session_id": session_id,
                "payload_id": payload_id,
                "chunk_index": idx,
                "total_chunks": num_chunks,
                "nonce": enc_info["nonce"],
                "ciphertext": enc_info["ciphertext"],
                "auth_tag": enc_info["auth_tag"],
                "hmac_sha256": enc_info["hmac_sha256"]
            }
            chunks.append(chunk_frame)
            
        return chunks

    @classmethod
    def reassemble_payload(
        cls,
        chunks: List[Dict[str, Any]],
        aes_key: bytes,
        hmac_key: bytes
    ) -> bytes:
        """Sorts, decrypts, and reassembles payload frames."""
        sorted_chunks = sorted(chunks, key=lambda c: c["chunk_index"])
        total_chunks = sorted_chunks[0]["total_chunks"]
        
        if len(sorted_chunks) != total_chunks:
            raise ValueError(f"Missing chunks: received {len(sorted_chunks)} / {total_chunks}")

        assembled = bytearray()
        for idx, chunk in enumerate(sorted_chunks):
            if chunk["chunk_index"] != idx:
                raise ValueError(f"Chunk sequence mismatch: expected index {idx}, got {chunk['chunk_index']}")
            
            session_id = chunk["session_id"]
            payload_id = chunk["payload_id"]
            ad = f"{session_id}:{payload_id}:{idx}:{total_chunks}".encode('utf-8')
            
            decrypted_slice = CryptoEngine.decrypt_chunk(chunk, aes_key, hmac_key, ad)
            assembled.extend(decrypted_slice)
            
        return bytes(assembled)
