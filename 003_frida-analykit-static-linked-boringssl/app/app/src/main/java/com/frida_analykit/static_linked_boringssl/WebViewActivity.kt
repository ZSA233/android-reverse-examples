package com.frida_analykit.static_linked_boringssl

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.GestureDetector
import android.view.MotionEvent
import android.webkit.*
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.addCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import kotlin.math.abs

private const val EXTRA_URL = "extra_url"


class WebViewActivity : ComponentActivity() {
    private lateinit var webView: WebView

    companion object {
        fun createIntent(context: Context, url: String): Intent {
            return Intent(context, WebViewActivity::class.java).apply {
                putExtra(EXTRA_URL, url)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val url = intent.getStringExtra(EXTRA_URL) ?: run {
            finish()
            return
        }

        webView = WebView(this)
        setContent {
            Box(modifier = Modifier.fillMaxSize()) {
                WebViewScreen(
                    webView = webView,
                    url = url,
                    onBack = { finish() }
                )
            }
        }

        onBackPressedDispatcher.addCallback(this) {
            if (::webView.isInitialized && webView.canGoBack()) {
                webView.goBack()
            } else {
                finish()
            }
        }

    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WebViewScreen(webView: WebView, url: String, onBack: () -> Unit) {
    val context = LocalContext.current
    var progress by remember { mutableStateOf(0) }
    var title by remember { mutableStateOf("") }

    DisposableEffect(Unit) {
        onDispose { webView.destroy() }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // 顶部导航栏
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color.LightGray)
                .padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "✕",
                modifier = Modifier
                    .clickable { onBack() }
                    .padding(8.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(text = title, maxLines = 1, modifier = Modifier.weight(1f))
        }

        // 进度条
        if (progress in 1..99) {
            LinearProgressIndicator(
                progress = { progress / 100f },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        // WebView
        AndroidView(factory = {
            webView.apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                WebView.setWebContentsDebuggingEnabled(true)

                webChromeClient = object : WebChromeClient() {
                    override fun onProgressChanged(view: WebView?, newProgress: Int) {
                        progress = newProgress
                    }
                    override fun onReceivedTitle(view: WebView?, t: String?) {
                        title = t ?: ""
                    }
                }
                webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(
                        view: WebView, request: WebResourceRequest
                    ): Boolean {
                        val reqUrl = request.url.toString()
                        return if (reqUrl.startsWith("http")) {
                            false
                        } else {
                            try {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(reqUrl)))
                            } catch (e: Exception) {
                                Toast.makeText(context, "无法打开链接: $reqUrl", Toast.LENGTH_SHORT).show()
                            }
                            true
                        }
                    }
                }

                loadUrl(url)
            }
        }, modifier = Modifier.fillMaxSize())
    }
}