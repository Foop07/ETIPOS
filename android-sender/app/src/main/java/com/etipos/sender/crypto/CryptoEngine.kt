package com.etipos.sender.crypto

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ETIPOS Android Kotlin Cryptographic Engine.
 * Implements X25519/ECDH, HKDF-SHA256, AES-256-GCM AEAD, and HMAC-SHA256.
 */
object CryptoEngine {

    private const val AES_KEY_SIZE = 32
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH = 128 // bits

    private val secureRandom = SecureRandom()

    fun generateRandomBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    /**
     * HKDF Extract-and-Expand (RFC 5869) using HMAC-SHA256.
     */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray = "ETIPOS-v1.0-SALT".toByteArray(), info: ByteArray = "ETIPOS-SESSION-KEYS".toByteArray(), outputLength: Int = 64): ByteArray {
        // Step 1: Extract
        val macExtract = Mac.getInstance("HmacSHA256")
        macExtract.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = macExtract.doFinal(ikm)

        // Step 2: Expand
        val macExpand = Mac.getInstance("HmacSHA256")
        macExpand.init(SecretKeySpec(prk, "HmacSHA256"))

        val result = ByteArrayOutputStream()
        var previousT = ByteArray(0)
        var counter: Byte = 1

        while (result.size() < outputLength) {
            macExpand.reset()
            if (previousT.isNotEmpty()) {
                macExpand.update(previousT)
            }
            macExpand.update(info)
            macExpand.update(counter)
            previousT = macExpand.doFinal()
            result.write(previousT)
            counter++
        }

        val allBytes = result.toByteArray()
        return allBytes.copyOfRange(0, outputLength)
    }

    /**
     * Encrypts plaintext bytes using AES-256-GCM and calculates HMAC-SHA256 integrity tag.
     */
    fun encryptChunk(
        plaintext: ByteArray,
        aesKey: ByteArray,
        hmacKey: ByteArray,
        associatedData: ByteArray = ByteArray(0)
    ): EncryptedChunkResult {
        val iv = generateRandomBytes(GCM_IV_LENGTH)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(aesKey, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }

        val fullCiphertext = cipher.doFinal(plaintext)
        val cipherLen = fullCiphertext.size - 16
        val ciphertext = fullCiphertext.copyOfRange(0, cipherLen)
        val authTag = fullCiphertext.copyOfRange(cipherLen, fullCiphertext.size)

        // Calculate HMAC-SHA256 over IV + Ciphertext + Tag + AAD
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
        mac.update(iv)
        mac.update(ciphertext)
        mac.update(authTag)
        mac.update(associatedData)
        val hmacTag = mac.doFinal()

        return EncryptedChunkResult(
            nonceB64 = Base64.getEncoder().encodeToString(iv),
            ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext),
            authTagB64 = Base64.getEncoder().encodeToString(authTag),
            hmacB64 = Base64.getEncoder().encodeToString(hmacTag)
        )
    }

    /**
     * Decrypts AES-256-GCM chunk and verifies HMAC.
     */
    fun decryptChunk(
        nonceB64: String,
        ciphertextB64: String,
        authTagB64: String,
        hmacB64: String,
        aesKey: ByteArray,
        hmacKey: ByteArray,
        associatedData: ByteArray = ByteArray(0)
    ): ByteArray {
        val iv = Base64.getDecoder().decode(nonceB64)
        val ciphertext = Base64.getDecoder().decode(ciphertextB64)
        val authTag = Base64.getDecoder().decode(authTagB64)
        val expectedHmac = Base64.getDecoder().decode(hmacB64)

        // 1. Verify HMAC
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
        mac.update(iv)
        mac.update(ciphertext)
        mac.update(authTag)
        mac.update(associatedData)
        val computedHmac = mac.doFinal()

        if (!MessageDigest.isEqual(computedHmac, expectedHmac)) {
            throw SecurityException("ETIPOS HMAC verification failed: Tampering detected!")
        }

        // 2. Decrypt GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(aesKey, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }

        val combined = ByteArray(ciphertext.size + authTag.size)
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.size)
        System.arraycopy(authTag, 0, combined, ciphertext.size, authTag.size)

        return cipher.doFinal(combined)
    }
}

data class EncryptedChunkResult(
    val nonceB64: String,
    val ciphertextB64: String,
    val authTagB64: String,
    val hmacB64: String
)

