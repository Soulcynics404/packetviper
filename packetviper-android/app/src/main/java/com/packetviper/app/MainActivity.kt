package com.packetviper.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { Screen() }
            }
        }
    }
}

@Composable
private fun Screen() {
    val ctx = LocalContext.current
    var link by remember { mutableStateOf(savedLink(ctx)) }
    var shown by remember { mutableStateOf(savedLink(ctx)) } // link the dashboard view is showing
    val valid = eventsUrl(link) != null
    val askNotify = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}

    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = link,
            onValueChange = { link = it },
            label = { Text("Connect link (press o on the laptop, then Scan QR)") },
            isError = link.isNotBlank() && !valid,
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        val start = { l: String ->
            saveLink(ctx, l)
            shown = l.trim()
            if (Build.VERSION.SDK_INT >= 33) askNotify.launch(Manifest.permission.POST_NOTIFICATIONS)
            val svc = Intent(ctx, AlertService::class.java)
            ctx.stopService(svc) // restart so a changed link takes effect
            ContextCompat.startForegroundService(ctx, svc)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                // Play Services scanner: no camera permission needed, the scan UI runs outside the app.
                GmsBarcodeScanning.getClient(ctx, GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
                    .startScan()
                    .addOnSuccessListener { code ->
                        val scanned = code.rawValue?.trim().orEmpty()
                        if (eventsUrl(scanned) != null) { link = scanned; start(scanned) }
                        else Toast.makeText(ctx, "Not a PacketViper connect QR", Toast.LENGTH_LONG).show()
                    }
                    .addOnFailureListener { Toast.makeText(ctx, "Scanner unavailable: ${it.message}", Toast.LENGTH_LONG).show() }
            }) { Text("Scan QR") }
            Button(enabled = valid, onClick = { start(link) }) { Text("Save & start") }
            OutlinedButton(onClick = { ctx.stopService(Intent(ctx, AlertService::class.java)) }) { Text("Stop") }
        }
        if (eventsUrl(shown) != null) Dashboard(shown, Modifier.weight(1f).fillMaxWidth())
    }
}

/** The laptop's own web dashboard: reuses all of its live views and controls. */
@SuppressLint("SetJavaScriptEnabled")
@Composable
private fun Dashboard(url: String, modifier: Modifier) = AndroidView(
    modifier = modifier,
    factory = { c ->
        WebView(c).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            webViewClient = WebViewClient() // keep navigation inside the app
        }
    },
    // Compare with the last link we loaded, not it.url: the page may change its own URL.
    update = { if (it.tag != url) { it.tag = url; it.loadUrl(url) } },
)
