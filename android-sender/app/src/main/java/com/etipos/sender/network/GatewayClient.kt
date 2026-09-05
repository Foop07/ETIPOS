package com.etipos.sender.network

import com.etipos.sender.crypto.CryptoEngine
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

data class ChunkFrame(
    val sessionId: String,
    val payloadId: String,
    val chunkIndex: Int,
    val totalChunks: Int,
    val nonce: String,
    val ciphertext: String,
    val authTag: String,
    val hmacSha256: String
)

class PayloadChunker(private val chunkSize: Int = 32 * 1024) {

    fun chunkAndEncrypt(
        payloadBytes: ByteArray,
        sessionId: String,
        payloadId: String,
        aesKey: ByteArray,
        hmacKey: ByteArray
    ): List<ChunkFrame> {
        val totalSize = payloadBytes.size
        val numChunks = if (totalSize > 0) (totalSize + chunkSize - 1) / chunkSize else 1
        val frames = mutableListOf<ChunkFrame>()

        for (idx in 0 until numChunks) {
            val start = idx * chunkSize
            val end = minOf(start + chunkSize, totalSize)
            val slice = payloadBytes.copyOfRange(start, end)

            val ad = "$sessionId:$payloadId:$idx:$numChunks".toByteArray()
            val encResult = CryptoEngine.encryptChunk(slice, aesKey, hmacKey, ad)

            frames.add(
                ChunkFrame(
                    sessionId = sessionId,
                    payloadId = payloadId,
                    chunkIndex = idx,
                    totalChunks = numChunks,
                    nonce = encResult.nonceB64,
                    ciphertext = encResult.ciphertextB64,
                    authTag = encResult.authTagB64,
                    hmacSha256 = encResult.hmacB64
                )
            )
        }
        return frames
    }
}

class GatewayClient(private val baseUrl: String) {

    fun performHandshake(senderId: String, clientPubKeyB64: String): JSONObject {
        val url = URL("$baseUrl/api/handshake")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true

        val payload = JSONObject().apply {
            put("sender_id", senderId)
            put("client_ephemeral_public_key", clientPubKeyB64)
        }

        OutputStreamWriter(conn.outputStream).use { it.write(payload.toString()) }

        val responseText = conn.inputStream.bufferedReader().use { it.readText() }
        return JSONObject(responseText)
    }

    fun uploadChunk(chunk: ChunkFrame): JSONObject {
        val url = URL("$baseUrl/api/payload/chunk")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true

        val payload = JSONObject().apply {
            put("session_id", chunk.sessionId)
            put("payload_id", chunk.payloadId)
            put("chunk_index", chunk.chunkIndex)
            put("total_chunks", chunk.totalChunks)
            put("nonce", chunk.nonce)
            put("ciphertext", chunk.ciphertext)
            put("auth_tag", chunk.authTag)
            put("hmac_sha256", chunk.hmacSha256)
        }

        OutputStreamWriter(conn.outputStream).use { it.write(payload.toString()) }
        val responseText = conn.inputStream.bufferedReader().use { it.readText() }
        return JSONObject(responseText)
    }

    fun triggerAssembleAndInspect(sessionId: String, payloadId: String, filename: String): JSONObject {
        val url = URL("$baseUrl/api/payload/$payloadId/assemble-and-inspect?session_id=$sessionId&filename=$filename")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        val responseText = conn.inputStream.bufferedReader().use { it.readText() }
        return JSONObject(responseText)
    }
}

