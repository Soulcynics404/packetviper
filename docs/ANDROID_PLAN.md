# PacketViper — Native Android App Plan (Phase 3)

Goal (user-confirmed): a Kotlin + Jetpack Compose app that is **both** a companion for the laptop
PacketViper **and**, later, a standalone on-device scanner. Distributed as an **APK** (not Play Store);
the Connect QR links to the APK download (host it on the user's AWS box / relay).

## Why native (vs the existing web dashboard)
The web dashboard already shows everything and controls the laptop. The native app exists for the one
thing a browser can't do: **reliable danger alerts when the app is closed / screen off** (background
service / push), plus saved pairing, a home-screen icon, and same-Wi-Fi auto-discovery.

## Toolchain status on this machine
- Installed: Android SDK (platform android-34, build-tools 34.0.0), platform-tools/adb, Java 21,
  Gradle 8.9 cached under `~/.gradle/wrapper/dists`. `ANDROID_HOME=~/Android/Sdk`.
- **Missing (install before M2 — standalone/Rust-on-phone):**
  ```
  sdkmanager "ndk;26.1.10909125"
  cargo install cargo-ndk
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  ```
- Cannot run an APK on a device from this environment; builds are verified by `assembleDebug` only.

## Milestones

### M1 — Companion app (do first; the shared foundation)
- New dir `packetviper-android/` (separate Gradle project; keep out of the Rust workspace).
- Compose UI: a Settings/pair screen (save a dashboard URL + token, or scan the QR) and a main screen.
  Fastest first cut: a `WebView` of the existing `ui/dashboard.html` served by the laptop — reuses all UI.
- **Foreground service** that holds a connection (SSE to `GET /api/events?t=` on LAN, or the relay
  `/r/<code>/events`) and raises a **system notification + sound + vibration** when `danger` is true,
  even with the app closed. This is the core value.
- Pairing input = the same token/relay link the `o` (Connect) screen shows. QR scanning via CameraX +
  ML Kit barcode can come after a manual-URL first cut.
- Build: generate the wrapper with cached Gradle 8.9 (`gradle wrapper --gradle-version 8.9`), then
  `./gradlew assembleDebug`. Target/compileSdk 34, minSdk ~26.

### M2 — Standalone scanner (bigger)
- Android `VpnService` to capture the phone's own traffic (TUN). Non-root sees only this phone's
  flows and no L2/ARP; root (or a rooted device) unlocks the full detector.
- Reuse `packetviper-core` on device via **JNI** (`cargo-ndk` builds `.so` for arm64/armv7; a thin
  `jni` bridge exposes the parser/detector). Feed TUN packets in, get alerts out.
- Be honest in-app about what non-root can/can't detect (same limits as documented for the desktop).

### M3 — FCM push
- Replace/augment the foreground service with Firebase Cloud Messaging for battery-friendly push that
  survives the app being killed. Needs a Firebase project and the **relay** to send push on new
  High/Critical alerts (add an FCM sender to `packetviper-relay`, keyed per room).

## Server-side touchpoints already in place
- LAN: `GET /api/events` (SSE), `GET /api/state`, `POST /api/config` (token `?t=`).
- Relay: `GET /r/<code>/events` (SSE). Room code = `sha256(push_key)`; laptop pushes with `X-Push-Key`.
- The app consumes the same JSON `Snapshot` shape (see `server.rs::Snapshot`).

## Open decisions for M1 start
- WebView-first vs native Compose screens for the dashboard (WebView is faster to ship; native is nicer).
- Where the APK is hosted so the QR can link to it (user's AWS box is the likely spot).
