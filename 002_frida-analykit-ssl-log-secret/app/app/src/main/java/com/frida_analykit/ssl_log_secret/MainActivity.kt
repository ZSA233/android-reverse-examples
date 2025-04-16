package com.frida_analykit.ssl_log_secret

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
import com.frida_analykit.ssl_log_secret.ui.theme.FridaanalykitssllogsecretTheme
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
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

const val GITHUB_URL = "https://github.com/zsa233/android-reverse-examples"
const val APP_TITLE = "002_frida-analykit-ssl-log-secret"
var globalOkHttpClient: OkHttpClient = OkHttpClient.Builder().build()


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            FridaanalykitssllogsecretTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    CertificatePinningScreen()
                }
            }
        }
    }
}

@Composable
fun CertificatePinningScreen() {
    val coroutineScope = rememberCoroutineScope()

    var urlInput by remember { mutableStateOf("https://www.qq.com/") }
    var editableFingerprint by remember { mutableStateOf("") }
    var savedFingerprint by remember { mutableStateOf("") }
    var sslPinningEnabled by remember { mutableStateOf(false) }
    var requestResult by remember { mutableStateOf("") }
    val resultTextScrollState = rememberScrollState()

    var openWebView by remember { mutableStateOf(false) }
    var currentUrlForWebView by remember { mutableStateOf("") }

    LaunchedEffect(savedFingerprint, sslPinningEnabled) {
        globalOkHttpClient = if (sslPinningEnabled && savedFingerprint.isNotEmpty()) {
            val host = URL(urlInput).host
            val certificatePinner = CertificatePinner.Builder()
                .add(host, savedFingerprint).build()
            Log.i("okhttp-client", "生成ssl pinning的client $host")
            OkHttpClient.Builder().certificatePinner(certificatePinner).build()
        } else {
            Log.i("okhttp-client", "无ssl pinning的client")
            OkHttpClient.Builder().build()
        }
    }

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

                Text(text = "通过 HTTPS URL 获取证书/发起请求：")

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
                            try {
                                requestResult = fetchCertificateFingerprintFromUrl(urlInput)
                                editableFingerprint = requestResult
                            } catch (e: Exception) {
                                requestResult = "Error: ${e.localizedMessage}"
                            }
                        }
                    }) {
                        Text(text = "获取证书")
                    }
                    Button(onClick = {
                        coroutineScope.launch {
                            try {
                                requestResult = performRequestUsingOkHttp(urlInput)
                            } catch (e: Exception) {
                                requestResult = "Error: ${e.localizedMessage}"
                            }
                        }
                    }) {
                        Text(text = "发起请求")
                    }
                }
                if (sslPinningEnabled) {
                    Text(text = "当前处于 SSL Pinning 模式", color = Color.Red)
                }
                HorizontalDivider()

                OutlinedTextField(
                    value = editableFingerprint,
                    onValueChange = { editableFingerprint = it },
                    label = { Text("证书公钥 SHA256 指纹") },
                    modifier = Modifier.fillMaxWidth()
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(onClick = {
                        savedFingerprint = editableFingerprint
                    }) {
                        Text("保存")
                    }
                    Button(onClick = {
                        editableFingerprint = ""
                        savedFingerprint = ""
                    }) {
                        Text("清空")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(text = "SSL Pinning")
                        Spacer(modifier = Modifier.width(4.dp))
                        Switch(
                            checked = sslPinningEnabled,
                            onCheckedChange = { sslPinningEnabled = it },
                            colors = SwitchDefaults.colors(checkedThumbColor = Color.Green)
                        )
                    }
                }

                Text(
                    text = "当前已保存指纹信息：$savedFingerprint",
                    color = Color.Blue,
                    modifier = Modifier.padding(top = 8.dp)
                )
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
    fontSize: TextUnit = 20.sp,
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



suspend fun fetchCertificateFingerprintFromUrl(urlString: String): String = withContext(Dispatchers.IO) {
    val url = URL(urlString)
    // 请求真实服务证书指纹时不走代理
    val connection = url.openConnection(Proxy.NO_PROXY) as HttpsURLConnection
    connection.connectTimeout = 5000
    connection.readTimeout = 5000
    connection.connect()
    val certificates = connection.serverCertificates
    if (certificates.isNotEmpty()) {
        val certificate = certificates[0] as X509Certificate
        val publicKeyEncoded = certificate.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(publicKeyEncoded)
        val base64Hash = Base64.encodeToString(hash, Base64.NO_WRAP)
        "sha256/$base64Hash"
    } else {
        throw Exception("未获取到服务器证书")
    }
}


suspend fun performRequestUsingOkHttp(urlString: String): String = withContext(Dispatchers.IO) {
    val userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
            "AppleWebKit/537.36 (KHTML, like Gecko) " +
            "Chrome/122.0.0.0 Safari/537.36"

    val request = Request.Builder()
        .url(urlString)
        .header("User-Agent", userAgent)
        .build()
    val response = globalOkHttpClient.newCall(request).execute()
    val result = response.body?.string()
    val currentTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
    if (response.isSuccessful) {
        "<$currentTime>\nOK - code[${response.code}]: ${(result?.length)} bytes"
    } else {
        "<$currentTime>\nERROR - code[${response.code}]: ${result?.length} bytes"
    }
}
