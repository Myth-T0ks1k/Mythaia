package com.mythaia.ui.proxy

import android.content.ClipData
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Hands a list of share links to the system share sheet, where they can be
 * copied, sent to a messenger or saved.
 *
 * A short list goes as text. A long one goes as a file: a bulk list runs to
 * megabytes, which does not fit the Binder transaction an Intent travels in,
 * and sharing it as text would crash with TransactionTooLargeException.
 */
internal object LinkExport {

    /** The longest list shared inline; anything longer becomes a file. */
    private const val MAX_INLINE_CHARS = 100_000

    suspend fun share(context: Context, links: String, title: String) {
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, title)
        if (links.length <= MAX_INLINE_CHARS) {
            intent.putExtra(Intent.EXTRA_TEXT, links)
        } else {
            val file = withContext(Dispatchers.IO) {
                val dir = File(context.cacheDir, EXPORT_DIR).apply { mkdirs() }
                // Only the latest export is kept; older ones would pile up in the cache.
                dir.listFiles()?.forEach { it.delete() }
                File(dir, fileName(title)).apply { writeText(links) }
            }
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.exports", file)
            intent.putExtra(Intent.EXTRA_STREAM, uri)
            intent.clipData = ClipData.newRawUri(title, uri)
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, title))
    }

    /** A file name from the group's name: letters, digits, spaces, dots, dashes. */
    private fun fileName(title: String): String {
        val safe = title.filter { it.isLetterOrDigit() || it in " ._-" }.trim().take(60)
        return (safe.ifEmpty { "servers" }) + ".txt"
    }

    private const val EXPORT_DIR = "exports"
}
