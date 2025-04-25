package com.frida_analykit.static_linked_boringssl

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.frida_analykit.static_linked_boringssl.ui.theme.FridaanalykitstaticlinkedboringsslTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.FlutterEngineCache
import io.flutter.embedding.engine.dart.DartExecutor
import io.flutter.plugin.common.MethodChannel
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

const val GITHUB_URL = "https://github.com/zsa233/android-reverse-examples"
const val APP_TITLE = "003_frida-analykit-static-linked-boringssl"
var globalOkHttpClient: OkHttpClient = OkHttpClient.Builder().build()


class MainActivity : ComponentActivity() {
    private lateinit var methodChannel: MethodChannel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val flutterEngine = FlutterEngine(this)
        flutterEngine.dartExecutor.executeDartEntrypoint(
            DartExecutor.DartEntrypoint.createDefault()
        )
        FlutterEngineCache.getInstance().put("my_engine", flutterEngine)

        methodChannel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            "com.frida_analykit.static_linked_boringssl-demo"
        )

        enableEdgeToEdge()
        setContent {


            FridaanalykitstaticlinkedboringsslTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    CertificatePinningScreen(
                        onOpenWebView    = { url -> startActivity(WebViewActivity.createIntent(this, url)) },
                        methodChannel    = methodChannel
                    )
                }
            }
        }
    }
}

@Composable
fun CertificatePinningScreen(
    onOpenWebView: (String) -> Unit,
    methodChannel: MethodChannel,
) {
    val coroutineScope = rememberCoroutineScope()

    var urlInput by remember { mutableStateOf("https://www.qq.com/") }
    val resultTextScrollState = rememberScrollState()
    var useFlutter by remember { mutableStateOf(true) }
    var requestResult by remember { mutableStateOf("") }


    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(WindowInsets.statusBars.asPaddingValues())
            .padding(horizontal = 6.dp)) {

        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            AppProjectTitle(APP_TITLE, GITHUB_URL)

            OutlinedTextField(
                value = urlInput,
                onValueChange = { urlInput = it },
                label = { Text("输入 HTTPS URL") },
                modifier = Modifier.fillMaxWidth()
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Button(onClick = {
                    coroutineScope.launch {
                        if (urlInput.isNotBlank()) {
                            onOpenWebView(urlInput)
                        }
                    }
                }) {
                    Text(text = "WebView打开")
                }
                Button(onClick = {
                    coroutineScope.launch {
                        if (useFlutter) {
                            val currentTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
                            methodChannel.invokeMethod(
                                "performRequest", mapOf("url" to urlInput),
                                object : MethodChannel.Result {
                                    override fun success(result: Any?) {
                                        requestResult = "<${currentTime}>\n${result as? String ?: "Dart 返回非字符串"}"
                                    }
                                    override fun error(code: String, msg: String?, details: Any?) {
                                        requestResult = "<${currentTime}>\nError: $msg"
                                    }
                                    override fun notImplemented() {
                                        requestResult = "Method not implemented."
                                    }
                                }
                            )
                        } else {
                            coroutineScope.launch(Dispatchers.IO) {
                                val res = performRequestUsingOkHttp(urlInput)
                                requestResult = res
                            }
                        }
                    }
                }) {
                    Text(text = "发起请求")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Flutter")
                    Switch(checked = useFlutter, onCheckedChange = { useFlutter = it })
                }
            }


            HorizontalDivider()

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(resultTextScrollState)
            ) {
                Text(text = "请求结果：$requestResult")
            }


        }
    }
}


@Composable
fun AppProjectTitle(
    title: String,
    githubUrl: String,
    fontSize: TextUnit = 18.sp,
    paddingVertical: Dp = 16.dp
) {
    val uriHandler = LocalUriHandler.current


    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.primaryContainer)
            .padding(horizontal = 16.dp, vertical = paddingVertical)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = title,
                modifier = Modifier.align(Alignment.CenterHorizontally),
                style = TextStyle(
                    fontSize = fontSize,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    textAlign = TextAlign.Center
                )
            )
            Text(
                text = "GitHub",
                modifier = Modifier
                    .align(Alignment.End)
                    .clickable { uriHandler.openUri(githubUrl) },
                style = TextStyle(
                    color = MaterialTheme.colorScheme.primary,
                    fontSize = 12.sp,
                    textDecoration = TextDecoration.Underline,
                    fontWeight = FontWeight.Medium
                )
            )
        }
    }
}


suspend fun performRequestUsingOkHttp(urlString: String): String = withContext(Dispatchers.IO) {
    val userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
            "AppleWebKit/537.36 (KHTML, like Gecko) " +
            "Chrome/122.0.0.0 Safari/537.36"

    val currentTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
    val request = Request.Builder()
        .url(urlString)
        .header("User-Agent", userAgent)
        .header("X", "okhttp")
        .build()
    val response = globalOkHttpClient.newCall(request).execute()
    val result = response.body?.string()
    if (response.isSuccessful) {
        "<$currentTime>\nOK - code[${response.code}]: ${(result?.length)} bytes"
    } else {
        "<$currentTime>\nERROR - code[${response.code}]: ${result?.length} bytes"
    }
}
