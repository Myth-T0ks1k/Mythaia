package com.argsment.anywhere.ui.scanner

import android.Manifest
import com.argsment.anywhere.vpn.util.AnywhereLogger
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathOperation
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import com.argsment.anywhere.R
import com.argsment.anywhere.ui.theme.Bone
import com.argsment.anywhere.ui.theme.DeepInk
import com.argsment.anywhere.ui.theme.Ink
import com.argsment.anywhere.ui.theme.LightAzure
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors

@Composable
fun QrScannerScreen(
    onResult: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var hasCameraPermission by remember { mutableStateOf(false) }
    var permissionDenied by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
        if (!granted) permissionDenied = true
    }

    LaunchedEffect(Unit) {
        val permission = Manifest.permission.CAMERA
        if (ContextCompat.checkSelfPermission(context, permission) == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            hasCameraPermission = true
        } else {
            permissionLauncher.launch(permission)
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        // The scanner is deliberately fixed dark chrome in both themes: a camera
        // feed always sits under an ink scrim, so the Wing dark-context tokens
        // (DeepInk / Ink / LightAzure / Bone) are correct in light and dark mode.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(DeepInk)
        ) {
            when {
                hasCameraPermission -> {
                    CameraPreview(
                        onQrCodeDetected = { code ->
                            onResult(code)
                        }
                    )

                    // Ink scrim with a punched-out rounded viewfinder window,
                    // framed by four azure corner brackets.
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val window = 250.dp.toPx()
                        val left = (size.width - window) / 2f
                        val top = (size.height - window) / 2f
                        val right = left + window
                        val bottom = top + window
                        val radius = 28.dp.toPx()

                        val windowPath = Path().apply {
                            addRoundRect(
                                RoundRect(
                                    rect = Rect(left, top, right, bottom),
                                    cornerRadius = CornerRadius(radius)
                                )
                            )
                        }
                        val fullPath = Path().apply {
                            addRect(Rect(0f, 0f, size.width, size.height))
                        }
                        drawPath(
                            path = Path.combine(PathOperation.Difference, fullPath, windowPath),
                            color = Ink.copy(alpha = 0.55f)
                        )

                        val arm = 26.dp.toPx()
                        val strokeWidth = 3.dp.toPx()

                        fun bracket(build: Path.() -> Unit) {
                            drawPath(
                                path = Path().apply(build),
                                color = LightAzure,
                                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                            )
                        }
                        // Top-left
                        bracket {
                            moveTo(left, top + radius + arm)
                            lineTo(left, top + radius)
                            arcTo(Rect(left, top, left + 2 * radius, top + 2 * radius), 180f, 90f, false)
                            lineTo(left + radius + arm, top)
                        }
                        // Top-right
                        bracket {
                            moveTo(right - radius - arm, top)
                            lineTo(right - radius, top)
                            arcTo(Rect(right - 2 * radius, top, right, top + 2 * radius), 270f, 90f, false)
                            lineTo(right, top + radius + arm)
                        }
                        // Bottom-right
                        bracket {
                            moveTo(right, bottom - radius - arm)
                            lineTo(right, bottom - radius)
                            arcTo(Rect(right - 2 * radius, bottom - 2 * radius, right, bottom), 0f, 90f, false)
                            lineTo(right - radius - arm, bottom)
                        }
                        // Bottom-left
                        bracket {
                            moveTo(left + radius + arm, bottom)
                            lineTo(left + radius, bottom)
                            arcTo(Rect(left, bottom - 2 * radius, left + 2 * radius, bottom), 90f, 90f, false)
                            lineTo(left, bottom - radius - arm)
                        }
                    }

                    Text(
                        text = stringResource(R.string.scan_your_qr_code),
                        color = Bone,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier
                            .align(Alignment.Center)
                            .offset(y = 165.dp)
                    )
                }

                permissionDenied -> {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = stringResource(R.string.permission_denied),
                            color = Bone,
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = onDismiss,
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = LightAzure,
                                contentColor = DeepInk
                            )
                        ) {
                            Text(stringResource(R.string.ok))
                        }
                    }
                }
            }

            IconButton(
                onClick = onDismiss,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(16.dp)
            ) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = stringResource(R.string.cancel),
                    tint = Bone
                )
            }
        }
    }
}

@Composable
@androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
private fun CameraPreview(
    onQrCodeDetected: (String) -> Unit
) {
    val context = LocalContext.current
    // Use the hosting Activity's lifecycle (not the enclosing Dialog's
    // sub-lifecycle). Inside a Compose `Dialog`, `LocalLifecycleOwner`
    // resolves to a short-lived dialog-scoped owner whose state churns
    // during the CAMERA permission prompt (RESUMED → STARTED → CREATED
    // → STARTED → RESUMED). CameraX's `bindToLifecycle` can race that
    // transition and throw `IllegalArgumentException: Trying to create
    // use case with a LifecycleOwner that is in DESTROYED state`.
    // The Activity's lifecycle is stable for the duration of the scan.
    val lifecycleOwner = (context as? androidx.lifecycle.LifecycleOwner)
        ?: androidx.lifecycle.compose.LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val hasDetected = remember { java.util.concurrent.atomic.AtomicBoolean(false) }
    val disposed = remember { java.util.concurrent.atomic.AtomicBoolean(false) }

    val previewView = remember { PreviewView(context) }
    // Narrow the scanner to QR codes only — cuts ML Kit model surface,
    // speeds up first-scan initialization, and avoids matching the
    // protocol QR against irrelevant formats like PDF417 or Aztec.
    val barcodeScanner = remember {
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        BarcodeScanning.getClient(options)
    }
    val cameraProviderFutureRef = remember {
        androidx.compose.runtime.mutableStateOf<com.google.common.util.concurrent.ListenableFuture<ProcessCameraProvider>?>(null)
    }

    AndroidView(
        factory = { previewView },
        modifier = Modifier
            .fillMaxSize()
            .clip(RoundedCornerShape(0.dp))
    )

    DisposableEffect(Unit) {
        val logger = AnywhereLogger("QrScanner")
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        cameraProviderFutureRef.value = cameraProviderFuture

        cameraProviderFuture.addListener({
            if (disposed.get()) return@addListener
            val cameraProvider = try {
                cameraProviderFuture.get()
            } catch (e: Exception) {
                logger.debug("Failed to obtain camera provider: ${e.message}")
                return@addListener
            }

            // Bail out if the dialog's lifecycle has already moved past STARTED — binding
            // to a DESTROYED LifecycleOwner throws IllegalArgumentException on CameraX.
            if (!lifecycleOwner.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.CREATED)) {
                return@addListener
            }

            val preview = Preview.Builder().build().also {
                it.surfaceProvider = previewView.surfaceProvider
            }

            val resolutionSelector = ResolutionSelector.Builder()
                .setResolutionStrategy(
                    ResolutionStrategy(
                        Size(1280, 720),
                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER
                    )
                )
                .build()

            val imageAnalysis = ImageAnalysis.Builder()
                .setResolutionSelector(resolutionSelector)
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { analysis ->
                    analysis.setAnalyzer(executor) analyzerLoop@ { imageProxy ->
                        if (disposed.get() || hasDetected.get()) {
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        val mediaImage = imageProxy.image
                        if (mediaImage == null) {
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        // Anything that throws between here and the
                        // `process()` call would leak the `ImageProxy`
                        // and stall CameraX (the pipeline waits for the
                        // frame to close). A hardware-specific rotation
                        // value or a malformed YUV plane can make
                        // `InputImage.fromMediaImage` throw; guard it.
                        val inputImage = try {
                            InputImage.fromMediaImage(
                                mediaImage,
                                imageProxy.imageInfo.rotationDegrees
                            )
                        } catch (e: Exception) {
                            logger.debug("InputImage.fromMediaImage failed: ${e.message}")
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        val task = try {
                            barcodeScanner.process(inputImage)
                        } catch (e: Exception) {
                            // `process()` synchronously throws when the
                            // scanner has already been closed (dispose
                            // racing the analyzer thread).
                            logger.debug("Barcode process rejected: ${e.message}")
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        task
                            .addOnSuccessListener { barcodes ->
                                if (disposed.get()) return@addOnSuccessListener
                                for (barcode in barcodes) {
                                    if (barcode.valueType == Barcode.TYPE_TEXT ||
                                        barcode.valueType == Barcode.TYPE_URL ||
                                        barcode.valueType == Barcode.TYPE_UNKNOWN) {
                                        val value = barcode.rawValue
                                        if (value != null && hasDetected.compareAndSet(false, true)) {
                                            onQrCodeDetected(value)
                                            break
                                        }
                                    }
                                }
                            }
                            .addOnFailureListener { e ->
                                logger.debug("Barcode scan failed: ${e.message}")
                            }
                            .addOnCompleteListener {
                                imageProxy.close()
                            }
                    }
                }

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageAnalysis
                )
            } catch (e: Exception) {
                logger.debug("Camera bind failed: ${e.message}")
            }
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            disposed.set(true)
            try {
                val future = cameraProviderFutureRef.value
                if (future != null && future.isDone) {
                    future.get().unbindAll()
                }
            } catch (e: Exception) {
                AnywhereLogger("QrScanner").debug("onDispose unbind failed: ${e.message}")
            }
            try { barcodeScanner.close() } catch (_: Exception) {}
            try { executor.shutdown() } catch (_: Exception) {}
        }
    }
}
