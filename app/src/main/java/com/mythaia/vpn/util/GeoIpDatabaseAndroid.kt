package com.mythaia.vpn.util

import android.content.Context
import java.io.File
import java.io.InputStream

/** Where the imported database lives on Android. */
fun GeoIpDatabase.file(context: Context): File = File(context.filesDir, GeoIpDatabase.FILE_NAME)

fun GeoIpDatabase.load(context: Context) = load(file(context))

fun GeoIpDatabase.importFrom(context: Context, input: InputStream): Boolean =
    importInto(file(context), input)

fun GeoIpDatabase.clear(context: Context) = clear(file(context))
