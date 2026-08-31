package com.argsment.anywhere.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.ui.theme.Azure
import com.argsment.anywhere.ui.theme.Bone

private val iconResources = mapOf(
    "Telegram" to R.drawable.ic_brand_telegram,
    "Netflix" to R.drawable.ic_brand_netflix,
    "YouTube" to R.drawable.ic_brand_youtube,
    "Disney+" to R.drawable.ic_brand_disney_plus,
    "TikTok" to R.drawable.ic_brand_tiktok,
    "ChatGPT" to R.drawable.ic_brand_chatgpt,
    "Claude" to R.drawable.ic_brand_claude,
    "Gemini" to R.drawable.ic_brand_gemini,
)

/**
 * 40dp rounded icon tile. Known third-party services keep their brand image;
 * everything else renders the Mythaia Wing identity — a solid azure rounded
 * square with the bone WingMark. The tile is a fixed brand chip (like a
 * launcher icon), so it intentionally uses the brand constants in both themes.
 */
@Composable
fun AppIconView(
    name: String,
    modifier: Modifier = Modifier
) {
    val iconRes = iconResources[name]

    if (iconRes != null) {
        Image(
            painter = painterResource(iconRes),
            contentDescription = name,
            contentScale = ContentScale.Crop,
            modifier = modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
        )
    } else {
        Box(
            modifier = modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(Azure),
            contentAlignment = Alignment.Center
        ) {
            WingMark(
                color = Bone,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(7.dp)
            )
        }
    }
}
