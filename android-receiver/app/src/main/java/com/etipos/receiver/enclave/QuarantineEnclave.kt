package com.etipos.receiver.enclave

import com.etipos.receiver.crypto.SignatureVerifier
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Sandboxed Quarantine Enclave on Phone B (Receiver).
 * Implements Kim et al. (2015) & Shabtai et al. (2010) isolation principles.
 */
class QuarantineEnclave(private val sandboxDir: File) {

    private val quarantineDir = File(sandboxDir, "quarantine").apply { mkdirs() }
    private val secureVaultDir = File(sandboxDir, "secure_vault").apply { mkdirs() }

    data class EnclaveItem(
        val itemId: String,
        val filename: String,
        val sizeBytes: Long,
        val status: String, // "QUARANTINED" | "VERIFIED_RELEASED" | "BLOCKED"
        val threatReport: JSONObject?,
        val localFilePath: String
    )

    fun stageIncomingPayload(
        payloadBytes: ByteArray,
        filename: String,
        threatReport: JSONObject? = null
    ): EnclaveItem {
        val itemId = UUID.randomUUID().toString()
        val stagedFile = File(quarantineDir, "$itemId.staged")
        stagedFile.writeBytes(payloadBytes)

        return EnclaveItem(
            itemId = itemId,
            filename = filename,
            sizeBytes = payloadBytes.size.toLong(),
            status = "QUARANTINED",
            threatReport = threatReport,
            localFilePath = stagedFile.absolutePath
        )
    }

    /**
     * Verifies cryptographic signature and promotes payload from Quarantine into Secure Vault.
     */
    fun releaseToVault(
        item: EnclaveItem,
        gatewayPubKeyB64: String
    ): EnclaveItem {
        val report = item.threatReport ?: throw IllegalStateException("No threat report attached to item")
        
        val isValid = SignatureVerifier.verifyGatewaySignature(report, gatewayPubKeyB64)
        if (!isValid) {
            throw SecurityException("Cryptographic verification failed: Untrusted Gateway signature!")
        }

        val verdict = report.optString("verdict", "BLOCK")
        if (verdict == "BLOCK") {
            throw SecurityException("Enclave rejection: Payload is marked as BLOCKED by Gateway inspection!")
        }

        // Move file from quarantine to secure vault
        val stagedFile = File(item.localFilePath)
        val vaultFile = File(secureVaultDir, item.filename)
        stagedFile.copyTo(vaultFile, overwrite = true)
        stagedFile.delete()

        return item.copy(
            status = "VERIFIED_RELEASED",
            localFilePath = vaultFile.absolutePath
        )
    }

    fun listVaultItems(): List<File> {
        return secureVaultDir.listFiles()?.toList() ?: emptyList()
    }
}

