package com.etipos.sender.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.etipos.sender.crypto.CryptoEngine
import com.etipos.sender.network.GatewayClient
import com.etipos.sender.network.PayloadChunker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SenderAppScreen()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SenderAppScreen() {
    var gatewayHost by remember { mutableStateOf("http://192.168.1.100:8000") }
    var sessionStatus by remember { mutableStateOf("DISCONNECTED") }
    var messageText by remember { mutableStateOf("") }
    var logConsole by remember { mutableStateOf("ETIPOS Node 1 Initialized.\nReady to establish local tunnel.") }
    var isSending by remember { mutableStateOf(false) }

    val coroutineScope = rememberCoroutineScope()

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFF0A0F1D)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "ETIPOS SENDER",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Node 1: Untrusted Sender Enclave",
                        color = Color(0xFF00F0FF),
                        fontSize = 12.sp
                    )
                }
                Surface(
                    color = if (sessionStatus.contains("ESTABLISHED")) Color(0x3310B981) else Color(0x33EF4444),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = sessionStatus,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        color = if (sessionStatus.contains("ESTABLISHED")) Color(0xFF10B981) else Color(0xFFEF4444),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            // Gateway IP Configuration
            OutlinedTextField(
                value = gatewayHost,
                onValueChange = { gatewayHost = it },
                label = { Text("Gateway Endpoint (Node 2)", color = Color.Gray) },
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedBorderColor = Color(0xFF00F0FF),
                    unfocusedBorderColor = Color(0xFF334155)
                )
            )

            // Message Composer
            OutlinedTextField(
                value = messageText,
                onValueChange = { messageText = it },
                label = { Text("Encrypted Message Payload", color = Color.Gray) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(110.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedBorderColor = Color(0xFF00F0FF),
                    unfocusedBorderColor = Color(0xFF334155)
                )
            )

            // Transmit Button
            Button(
                onClick = {
                    coroutineScope.launch {
                        isSending = true
                        logConsole += "\n[+] Initiating X25519 Handshake with $gatewayHost..."
                        withContext(Dispatchers.IO) {
                            try {
                                val client = GatewayClient(gatewayHost)
                                // Mock ephemeral public key for demonstration handshake
                                val mockClientPubB64 = java.util.Base64.getEncoder().encodeToString(CryptoEngine.generateRandomBytes(32))
                                val handshakeRes = client.performHandshake("android-node-1", mockClientPubB64)
                                val sessionId = handshakeRes.getString("session_id")
                                
                                sessionStatus = "ESTABLISHED"
                                logConsole += "\n[+] Session Established: $sessionId"
                                logConsole += "\n[+] Deriving AES-256-GCM + HMAC keys via HKDF..."

                                val payloadBytes = messageText.ifEmpty { "ETIPOS Classified Telemetry Message" }.toByteArray()
                                val payloadId = UUID.randomUUID().toString()
                                val chunker = PayloadChunker(1024)

                                val mockKey = CryptoEngine.generateRandomBytes(32)
                                val frames = chunker.chunkAndEncrypt(payloadBytes, sessionId, payloadId, mockKey, mockKey)
                                logConsole += "\n[+] Uploading ${frames.size} encrypted chunks..."

                                for (f in frames) {
                                    client.uploadChunk(f)
                                }

                                logConsole += "\n[+] Requesting Gatekeeper Static & AI Inspection..."
                                val report = client.triggerAssembleAndInspect(sessionId, payloadId, "message.txt")
                                logConsole += "\n[+] Gatekeeper Verdict: " + report.getString("verdict")
                                logConsole += "\n[+] Risk Score: " + report.getDouble("composite_risk_score")

                            } catch (e: Exception) {
                                logConsole += "\n[-] Error: ${e.localizedMessage}"
                                sessionStatus = "FAILED"
                            } finally {
                                isSending = false
                            }
                        }
                    }
                },
                enabled = !isSending,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0284C7)),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text(
                    text = if (isSending) "ENCRYPTING & TRANSMITTING..." else "ENCRYPT & TRANSMIT TO GATEWAY",
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp
                )
            }

            // Real-time Console Log
            Text(
                text = "SECURITY TELEMETRY LOG",
                color = Color.Gray,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace
            )
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = logConsole,
                    modifier = Modifier.padding(12.dp),
                    color = Color(0xFF38BDF8),
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
    }
}

