package com.packetviper.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/** Saved pairing link: the LAN dashboard link (`http://ip:port/?t=TOKEN`) or the relay link (`https://host/r/CODE`). */
fun savedLink(ctx: Context): String = ctx.getSharedPreferences("pv", Context.MODE_PRIVATE).getString("link", "") ?: ""

fun saveLink(ctx: Context, link: String) =
    ctx.getSharedPreferences("pv", Context.MODE_PRIVATE).edit().putString("link", link.trim()).apply()

/** Maps a pairing link to its SSE stream URL, or null if the link isn't one PacketViper hands out. */
fun eventsUrl(link: String): String? {
    val u = runCatching { URI(link.trim()) }.getOrNull() ?: return null
    if (u.scheme != "http" && u.scheme != "https" || u.host.isNullOrEmpty()) return null
    val base = "${u.scheme}://${u.rawAuthority}"
    val path = u.rawPath.orEmpty().trimEnd('/')
    return if (path.startsWith("/r/")) "$base$path/events"
    else u.rawQuery?.takeIf { it.isNotEmpty() }?.let { "$base/api/events?$it" }
}

/**
 * Foreground service that holds the laptop's SSE stream open and raises a loud notification
 * whenever the laptop reports a new danger alarm — works with the app closed and the screen off.
 */
class AlertService : Service() {
    @Volatile private var running = true
    @Volatile private var conn: HttpURLConnection? = null
    private var worker: Thread? = null
    private var wake: PowerManager.WakeLock? = null
    private val nm by lazy { getSystemService(NotificationManager::class.java) }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        nm.createNotificationChannel(NotificationChannel(CH_STATUS, "Connection status", NotificationManager.IMPORTANCE_MIN))
        nm.createNotificationChannel(NotificationChannel(CH_DANGER, "Danger alerts", NotificationManager.IMPORTANCE_HIGH).apply {
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 600, 300, 600, 300, 600)
        })
        val status = status("Connecting…")
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(ID_STATUS, status, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(ID_STATUS, status)
        } catch (e: Exception) {
            // A sticky restart from the background can be refused on Android 12+; don't crash.
            running = false
            nm.notify(ID_DANGER, Notification.Builder(this, CH_DANGER)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("PacketViper alerts stopped")
                .setContentText("Open the app to turn danger alerts back on.")
                .setContentIntent(openApp())
                .setAutoCancel(true)
                .build())
            stopSelf()
            return
        }
        // ponytail: wake lock for the whole session keeps the socket read alive with the screen off;
        // costs battery. Swap for FCM push (M3) when that lands.
        wake = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "packetviper:alerts").apply { acquire() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val url = eventsUrl(savedLink(this))
        if (url == null || !running) { stopSelf(); return START_NOT_STICKY }
        if (worker == null) worker = Thread { loop(url) }.apply { isDaemon = true; start() }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        worker?.interrupt() // wakes it from the backoff sleep
        conn?.disconnect() // unblocks the reader thread
        wake?.release()
        super.onDestroy()
    }

    private fun loop(url: String) {
        var lastAlarm: String? = null // survives reconnects so a still-open alarm doesn't re-notify
        var backoff = 1000L
        while (running) {
            try {
                val c = (URL(url).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 10_000
                    readTimeout = 15_000 // server sends a snapshot every second; silence = dead link
                    setRequestProperty("Accept", "text/event-stream")
                }
                conn = c
                if (c.responseCode != 200) throw RuntimeException("HTTP ${c.responseCode}")
                if (!running) break
                nm.notify(ID_STATUS, status("Watching for danger"))
                backoff = 1000L
                c.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        if (!running) break
                        if (!line.startsWith("data:")) continue
                        val snap = runCatching { JSONObject(line.substring(5)) }.getOrNull() ?: continue
                        if (!snap.optBoolean("danger")) { lastAlarm = null; continue }
                        val text = snap.optString("danger_text").ifEmpty { "Danger on your network" }
                        if (text != lastAlarm && running) {
                            lastAlarm = text
                            danger(text, snap.optBoolean("danger_critical"))
                        }
                    }
                }
            } catch (e: Exception) {
                if (!running) break
                nm.notify(ID_STATUS, status("Reconnecting… (${e.message ?: e.javaClass.simpleName})"))
            } finally {
                conn?.disconnect()
            }
            try { Thread.sleep(backoff) } catch (_: InterruptedException) { break }
            backoff = (backoff * 2).coerceAtMost(30_000L)
        }
    }

    private fun openApp() = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
    )

    private fun status(text: String): Notification = Notification.Builder(this, CH_STATUS)
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .setContentTitle("PacketViper")
        .setContentText(text)
        .setContentIntent(openApp())
        .setOngoing(true)
        .build()

    private fun danger(text: String, critical: Boolean) = nm.notify(ID_DANGER, Notification.Builder(this, CH_DANGER)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle(if (critical) "CRITICAL threat on your network" else "Danger on your network")
        .setContentText(text)
        .setStyle(Notification.BigTextStyle().bigText(text))
        .setCategory(Notification.CATEGORY_ALARM)
        .setContentIntent(openApp())
        .setAutoCancel(true)
        .build())

    companion object {
        private const val CH_STATUS = "status"
        private const val CH_DANGER = "danger"
        private const val ID_STATUS = 1
        private const val ID_DANGER = 2
    }
}
