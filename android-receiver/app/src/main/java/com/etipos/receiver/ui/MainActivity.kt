package com.etipos.receiver.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import com.etipos.receiver.airgap.OpticalBurstScanner
import com.etipos.receiver.enclave.QuarantineEnclave
import org.json.JSONObject
import java.io.File

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ReceiverAppScreen(filesDir)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReceiverAppScreen(filesDir: File) {
    val enclave = remember { QuarantineEnclave(filesDir) }
    val scanner = remember { OpticalBurstScanner() }

    var scanProgress by remember { mutableStateOf(0f) }
    var enclaveStatus by remember { mutableStateOf("AIR-GAP SECURED") }
    var scannedPayloadText by remember { mutableStateOf<String?>(null) }
    var vaultItems by remember { mutableStateOf(enclave.listVaultItems()) }
    var logConsole by remember { mutableStateOf("ETIPOS Node 3 Air-Gapped Enclave Online.\nOptical Burst ingest ready.") }

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
                        text = "ETIPOS RECEIVER",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Node 3: Air-Gapped Quarantine Enclave",
                        color = Color(0xFFA855F7),
                        fontSize = 12.sp
                    )
                }
                Surface(
                    color = Color(0x33A855F7),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = enclaveStatus,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        color = Color(0xFFA855F7),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            // Optical Burst Progress Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(14.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "OPTICAL CAMERA BURST STREAM",
                            color = Color.White,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "${(scanProgress * 100).toInt()}%",
                            color = Color(0xFFA855F7),
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                    LinearProgressIndicator(
                        progress = { scanProgress },
                        modifier = Modifier.fillMaxWidth(),
                        color = Color(0xFFA855F7),
                        trackColor = Color(0xFF1E293B)
                    )
                }
            }

            // Staged & Vaulted Payload Section
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(14.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "SECURE MESSAGE & FILE VAULT",
                        color = Color(0xFF10B981),
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    if (scannedPayloadText != null) {
                        Surface(
                            color = Color(0xFF1E293B),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = "Decrypted Payload:\n$scannedPayloadText",
                                color = Color.White,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(10.dp)
                            )
                        }
                    } else {
                        Text(
                            text = "No quarantined items pending release. Camera QR stream scanning...",
                            color = Color.Gray,
                            fontSize = 11.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = logConsole,
                        color = Color(0xFF94A3B8),
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }
    }
}

