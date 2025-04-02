package com.example.frida_stalker_recompile_fix

import android.os.Bundle
import android.text.TextUtils
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.example.frida_stalker_recompile_fix.ui.theme.TestfridaTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            TestfridaTheme {
                val resultList = remember { mutableStateListOf<String>() }

                Scaffold(
                    modifier = Modifier
                        .fillMaxSize(),
                    floatingActionButton = { Trigger(resultList) },
                ) { innerPadding ->
                    Greeting(
                        resultList = resultList,
                        modifier = Modifier.padding(innerPadding)
                    )
                }

                System.loadLibrary("test_frida")
            }
        }
    }

    external fun mmapExec(insn1: ByteArray, insn2: ByteArray, num: Int): Array<String>
}

@Composable
fun Greeting(resultList: List<String>, modifier: Modifier = Modifier) {
    val formattedText = resultList.joinToString("\n")
    val scrollState = rememberScrollState()

    Text(
        text = formattedText,
        modifier = modifier.verticalScroll(scrollState)
    )
}

val emptyFunc = byteArrayOf(
    0xC0.toByte(), 0x03.toByte(), 0x5F.toByte(), 0xD6.toByte(),  // ret
)
val add99Func = byteArrayOf(
    0x00.toByte(), 0x8C.toByte(), 0x01.toByte(), 0x91.toByte(), // add x0, x0, #99
    0xC0.toByte(), 0x03.toByte(), 0x5F.toByte(), 0xD6.toByte(), // ret
)


@Composable
fun Trigger(resultList: SnapshotStateList<String>) {
    val activity = LocalContext.current as MainActivity

    val text = remember { mutableStateOf("执行") }
    val toggle = remember { mutableStateOf(false) }
    val counter = remember { mutableIntStateOf(0) }
    val isLoading = remember { mutableStateOf(false) }

    val coroutineScope = rememberCoroutineScope()
    Button(
        onClick = {
            if (!isLoading.value) {
                isLoading.value = true
                coroutineScope.launch {
                    text.value = "进行中..."
                    val results = withContext(Dispatchers.IO) {
                        toggle.value = !toggle.value
                        counter.intValue ++
                        val fn = listOf(emptyFunc, add99Func)
                        activity.mmapExec(fn[0], fn[1], 1)
                    }
                    val i = String.format(Locale.CHINA, "%03d", counter.intValue)
                    val result = TextUtils.join("\n", results)
                    resultList.add(0, "[$i]: \n $result \n")
                    isLoading.value = false
                }
            }
        },
        enabled = !isLoading.value
    ) {
        Text("开始执行")
    }
}
