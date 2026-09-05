package com.etipos.receiver.airgap

import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.CRC32
import java.util.zip.InflaterInputStream

/**
 * High-speed Optical QR Burst Scanner frame reassembly engine.
 * Implements Scaife et al. (2014) optical air-gap stream reception.
 */
class OpticalBurstScanner {

    private val receivedFrames = ConcurrentHashMap<Int, OpticalFrame>()
    private var totalExpectedFrames: Int = -1
    private var currentPayloadId: String? = null
    private var gatewaySignature: String = ""

    data class OpticalFrame(
        val version: Int,
        val payloadId: String,
        val frameIndex: Int,
        val totalFrames: Int,
        val checksumHex: String,
        val dataChunk: String,
        val signature: String = ""
    )

    fun reset() {
        receivedFrames.clear()
        totalExpectedFrames = -1
        currentPayloadId = null
        gatewaySignature = ""
    }

    /**
     * Processes a single scanned QR code string from camera feed.
     * Returns true if this frame completed the entire burst sequence.
     */
    fun ingestScannedFrame(rawQrJson: String): Boolean {
        val json = JSONObject(rawQrJson)
        val frame = OpticalFrame(
            version = json.getInt("v"),
            payloadId = json.getString("p"),
            frameIndex = json.getInt("i"),
            totalFrames = json.getInt("t"),
            checksumHex = json.getString("c"),
            dataChunk = json.getString("d"),
            signature = if (json.has("s")) json.getString("s") else ""
        )

        // Reset if payload ID changed
        if (currentPayloadId != null && currentPayloadId != frame.payloadId) {
            reset()
        }

        currentPayloadId = frame.payloadId
        totalExpectedFrames = frame.totalFrames
        if (frame.signature.isNotEmpty()) {
            gatewaySignature = frame.signature
        }

        // Validate CRC32
        val crc = CRC32()
        crc.update(frame.dataChunk.toByteArray())
        val calculatedHex = String.format("%08x", crc.value)
        if (!calculatedHex.equals(frame.checksumHex, ignoreCase = true)) {
            return false // Corrupted frame, skip
        }

        receivedFrames[frame.frameIndex] = frame
        return isComplete()
    }

    fun getProgress(): Float {
        if (totalExpectedFrames <= 0) return 0f
        return (receivedFrames.size.toFloat() / totalExpectedFrames).coerceIn(0f, 1f)
    }

    fun isComplete(): Boolean {
        if (totalExpectedFrames <= 0) return false
        return receivedFrames.size == totalExpectedFrames
    }

    /**
     * Reassembles and decompresses the full payload bytes upon complete reception.
     */
    fun assemblePayload(): ByteArray {
        if (!isComplete()) {
            throw IllegalStateException("Cannot assemble incomplete burst: received ${receivedFrames.size}/$totalExpectedFrames frames")
        }

        val sortedIndices = (0 until totalExpectedFrames)
        val sb = StringBuilder()
        for (i in sortedIndices) {
            val frame = receivedFrames[i] ?: throw IllegalStateException("Missing frame index $i")
            sb.append(frame.dataChunk)
        }

        val fullB64 = sb.toString()
        val compressedBytes = Base64.getDecoder().decode(fullB64)

        // Decompress zlib
        val inflater = InflaterInputStream(ByteArrayInputStream(compressedBytes))
        val bout = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        var n: Int
        while (inflater.read(buffer).also { n = it } != -1) {
            bout.write(buffer, 0, n)
        }
        return bout.toByteArray()
    }

    fun getGatewaySignature(): String = gatewaySignature
}

