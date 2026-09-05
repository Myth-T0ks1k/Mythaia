package com.mythaia.wear

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.wear.compose.material.Button
import androidx.wear.compose.material.ButtonDefaults
import androidx.wear.compose.material.CircularProgressIndicator
import androidx.wear.compose.material.Icon
import androidx.wear.compose.material.MaterialTheme
import androidx.wear.compose.material.Scaffold
import androidx.wear.compose.material.Text
import androidx.wear.compose.material.TimeText
import kotlinx.coroutines.launch

// The Wing palette, as much of it as a round screen needs. Wear is always dark:
// an OLED watch face is mostly black and a light sheet is blinding at night.
private val Azure = Color(0xFF24548F)
private val Bone = Color(0xFFF6F3EC)
private val Slate = Color(0xFF4E5568)

/**
 * The whole watch app: what the tunnel is doing, and one control to change it.
 *
 * There is nothing else here on purpose. Choosing a server, editing a profile
 * or reading a log are all things a phone screen does better, and a watch that
 * offers them is a watch the user gives up on.
 */
class WearMainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { TunnelScreen() }
    }
}

@Composable
private fun TunnelScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val link = remember { PhoneLink(context) }

    var status by remember { mutableStateOf(PhoneStatus.unknown) }

    DisposableEffect(link) {
        link.onStatus = { status = it }
        link.start()
        onDispose {
            link.onStatus = null
            link.stop()
        }
    }

    // Asked once on the way in; after that the phone reports each change, so
    // there is no poll draining the battery on the wrist.
    LaunchedEffect(link) { link.requestStatus() }

    Scaffold(timeText = { TimeText() }) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            val isOn = status.state == PhoneStatus.State.ON
            val isBusy = status.state == PhoneStatus.State.WORKING

            if (isBusy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(48.dp),
                    indicatorColor = Azure
                )
            } else {
                Button(
                    onClick = {
                        status = status.copy(state = PhoneStatus.State.WORKING)
                        scope.launch { if (isOn) link.disconnect() else link.connect() }
                    },
                    colors = ButtonDefaults.buttonColors(
                        backgroundColor = if (isOn) Azure else Slate
                    ),
                    modifier = Modifier.size(64.dp)
                ) {
                    Icon(
                        // The same pair the phone app uses for the tunnel, so
                        // the two faces of one product read as one product.
                        painter = painterResource(
                            if (isOn) R.drawable.ic_network_filled
                            else R.drawable.ic_network_outlined
                        ),
                        contentDescription = stringResource(
                            if (isOn) R.string.disconnect else R.string.connect
                        ),
                        tint = Bone
                    )
                }
            }

            Text(
                text = headline(status),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 12.dp),
                textAlign = TextAlign.Center,
                color = Bone,
                style = MaterialTheme.typography.title3
            )

            val detail = detail(status)
            if (detail.isNotEmpty()) {
                Text(
                    text = detail,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    textAlign = TextAlign.Center,
                    color = Slate,
                    style = MaterialTheme.typography.caption2
                )
            }
        }
    }
}

@Composable
private fun headline(status: PhoneStatus): String = when (status.state) {
    PhoneStatus.State.ON -> stringResource(R.string.connected)
    PhoneStatus.State.OFF -> stringResource(R.string.disconnected)
    PhoneStatus.State.WORKING -> stringResource(R.string.working)
    PhoneStatus.State.UNREACHABLE -> stringResource(R.string.no_phone)
    PhoneStatus.State.NEEDS_PHONE -> stringResource(R.string.needs_phone)
    PhoneStatus.State.NO_SERVER -> stringResource(R.string.no_server)
    PhoneStatus.State.FAILED -> stringResource(R.string.failed)
}

/** The server name, but only where it says something the headline does not. */
@Composable
private fun detail(status: PhoneStatus): String = when (status.state) {
    PhoneStatus.State.ON, PhoneStatus.State.OFF -> status.serverName
    else -> ""
}
