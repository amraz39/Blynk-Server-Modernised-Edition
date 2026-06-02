# Blynk Community Server — Modernised Edition

This is a hardened, modernised fork of the legacy self-hosted **Blynk Local Server** — an open-source IoT platform for connecting Arduino, ESP8266, ESP32, Raspberry Pi, and other microcontrollers to iOS and Android apps over the internet.

The original Blynk server project was **discontinued** by Blynk Inc. in favour of their commercial cloud platform. This fork updates it to run on modern Java runtimes and hardware, with significant security, compatibility, stability, and performance improvements.

> **Original project:** [https://github.com/blynkkk/blynk-server](https://github.com/blynkkk/blynk-server)

> **Original license:** [GNU GPL-3.0](https://github.com/blynkkk/blynk-server/blob/master/license.txt)

This project is an unofficial community-maintained fork and is not affiliated with or endorsed by Blynk Inc.

---

## What's New in This Fork

### Critical Bug Fixes
- Fixed `executeReportingDB` routing to wrong thread pool (was silently using `dbExecutor` instead of `dbReportingExecutor`)
- Fixed `dbReportingExecutor` never shut down on server close (thread leak)
- Fixed Docker `ASYNC_LOGGER_RING_BUGGER_SIZE` typo — log4j2 async ring buffer was silently defaulting to 256 slots instead of 2048 (8× throughput regression)
- Fixed HTTP admin sessions never invalidated on logout (memory leak + stolen cookie vulnerability)
- Fixed `v++` post-increment bug in statistics counters (counters never advanced past 1)
- Fixed Netty pipeline handler name typos (`HHArdwareHandler`, `HHArdwareMqttHandler`) that could cause silent `NoSuchElementException` at runtime
- Fixed admin login always failing due to double-password-hashing (browser pre-hashes, server was hashing again)

### Security Fixes
- **SSRF protection** on webhook URLs — blocks private IPs (`10.x`, `192.168.x`, `169.254.x`), loopback, and non-HTTP schemes
- **Path traversal protection** in static file server — canonical path guard prevents `%2e%2e%2f` bypass
- **Brute-force lockout** on admin login — 10 failed attempts triggers 15-minute IP lockout
- **Deserialization protection** — `ObjectInputStream` replaced with class-whitelisted `FilteredObjectInputStream` to block gadget-chain RCE attacks
- **File upload extension whitelist** — only `.bin`, `.hex`, `.jpg`, `.png`, `.gif` permitted (blocks `.sh`, `.jar`, `.php`, `.war` etc.)
- **Email sanitisation** in filesystem paths — prevents path traversal via crafted email addresses
- **OTA firmware path guard** — canonical path validation prevents directory traversal in firmware upload path
- **HTTP security headers** on all responses — `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- **CORS tightened** on admin endpoints — wildcard `Access-Control-Allow-Origin: *` removed from redirect responses
- **Constant-time password comparison** — `MessageDigest.isEqual()` replaces `.equals()` to prevent timing attacks
- **TLS 1.2/1.3 only** when `latest.tls=true` — applies to both custom and self-signed certificate paths
- **SRI hash mismatch fixed** in admin login page — removed stale integrity attributes that blocked jQuery/Bootstrap loading

### Performance Improvements
- Thread pool sizing fixed — `Math.max()` guards prevent integer division truncation to 0/1-thread pools
- `WriteBufferWaterMark(8KB/32KB)` added to Netty bootstrap — bounds per-channel outbound buffers during fan-out writes
- `TCP_NODELAY` enabled — reduces latency for small IoT messages
- `SO_BACKLOG=1024` — handles connection storms (many devices reconnecting after power cycle)
- `ReportScheduler` pool size now configurable via `report.scheduler.pool.size` (default: `max(2, cpuCores/2)`)
- `ReportScheduler.afterExecute()` added — prunes completed futures to prevent map unbounded growth
- Daily backup and history graph cleanup moved off the scheduler thread onto `blockingIOProcessor`
- `SimpleDateFormat` (not thread-safe) replaced with `DateTimeFormatter` throughout
- HikariCP `maxLifetime` set to 570 seconds (was 0 = infinite, preventing stale connection recycling)
- HikariCP pool size now configurable via `db.pool.size`; `connectionTestQuery` removed (HikariCP 3+ uses `isValid()`)
- `hard.socket.idle.timeout` code default raised from 0 (disabled) to 60 seconds

### Email / Gmail Fix
- Gmail App Password support — server now gives clear, actionable error messages instead of cryptic "check your network" when credentials are wrong
- `mail.smtp.ssl.trust`, `mail.smtp.ssl.protocols`, and `mail.smtp.writetimeout` added to default configuration
- Early warning logged at startup if username/password are unconfigured

### Docker Improvements
- Base image pinned to `ubuntu:24.04` (was `ubuntu:latest` — non-reproducible builds)
- Upgraded to OpenJDK 21 (was JDK 11 — caused `UnsupportedClassVersionError` at runtime)
- Maven removed from runtime image (~200 MB saved)
- Hardcoded default admin credentials removed
- Non-root `blynk` user added
- `HEALTHCHECK` added
- JVM tuning flags exposed via `JAVA_OPTS`
- `HARD_SOCKET_IDLE_TIMEOUT` default raised to 60 seconds

### ARM / Raspberry Pi 5 Support
- Added `unix-aarch64` Maven profile — bundles `linux-aarch_64` native JNI libraries for epoll and BoringSSL
- Without this, Netty silently fell back to NIO + JDK TLS (~20–30% throughput loss on RPi5)

### Deployment
- `systemd` service file included (`server/Docker/blynk-server.service`) with RPi5-optimised JVM flags
- Logrotate configuration recommended (see [Deployment](#deployment) section)
- Admin panel logout button added

### Code Quality
- Duplicated statistics counter methods in `UserDao` refactored into a shared `countByDeviceField()` helper
- `System.out.println` replaced with Log4j2 throughout all production classes
- `InterruptedException` handlers restored thread interrupt flag (was silently swallowed in `AcmeClient`)
- `ConfigsLogic` silent `IOException` catch now logs a warning

---

## Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Java | 21 | 21 (Temurin/OpenJDK) |
| RAM | 64 MB | 256 MB |
| OS | Any (Linux/Windows/macOS) | Ubuntu 24.04 / Raspberry Pi OS |
| Open ports | 9443, 8440 | 9443, 8440, 8084 |

---

## Building from Source

### Prerequisites

**1. Install Java 21**

- Download [Eclipse Temurin JDK 21](https://adoptium.net/) for your platform
- Set `JAVA_HOME`:
  - **Windows:** System Properties → Environment Variables → New System Variable → `JAVA_HOME` = `C:\Program Files\Eclipse Adoptium\jdk-21.x.x`
  - **Linux/macOS:** `export JAVA_HOME=/path/to/jdk-21`

**2. Install Maven 3.8+**

- Download [Apache Maven](https://maven.apache.org/download.cgi) and extract to e.g. `C:\Tools\apache-maven-3.9.x`
- Add Maven to PATH:
  - **Windows (GUI):** System Properties → Environment Variables → System Variables → `Path` → Edit → New → `C:\Tools\apache-maven-3.9.x\bin`
  - **Windows (PowerShell, run as Administrator):**
    ```powershell
    [System.Environment]::SetEnvironmentVariable(
      "Path",
      [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";C:\Tools\apache-maven-3.9.x\bin",
      "Machine"
    )
    ```
  - **Linux/macOS:** `export PATH=$PATH:/opt/maven/bin`
- Restart your terminal, then verify:
  ```bash
  mvn -version
  java -version
  ```

### Build

**Standard build (all platforms):**
```bash
mvn clean package "-DskipTests" "-Dcheckstyle.skip=true"
```

**For Raspberry Pi 5 / ARM64 (includes aarch64 native libraries: native epoll, JDK SSL provider):**
```bash
mvn clean package "-DskipTests" "-Dcheckstyle.skip=true" "-Depoll.os=linux-aarch_64"
```

The built JAR will be at:
```
server/launcher/target/server-0.41.18-SNAPSHOT.jar
```

### VSCode

Install the **Extension Pack for Java** (`vscjava.vscode-java-pack`). Once installed you will see a **Maven** panel in the Explorer sidebar — expand the project, go to **Lifecycle**, and click `package` to build with a single click.

---

## Deployment

### Running Manually

```bash
java -server -Xms64m -Xmx512m -XX:+UseZGC \
  -Dio.netty.leakDetection.level=disabled \
  -jar server-0.41.18-SNAPSHOT.jar \
  -dataFolder /opt/blynk/data \
  -serverConfig /opt/blynk/server.properties
```

### Raspberry Pi 5 — systemd Service

A production-ready systemd unit file is included at `server/Docker/blynk-server.service`. It includes:
- G1GC tuning optimised for RPi5's 4-core, low-heap profile
- Memory limits (`MemoryMax=384M`, `MemoryHigh=320M`)
- Swap disabled for the JVM process (SD card protection)
- Security hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`)
- Automatic restart with backoff

Install it:
```bash
sudo cp server/Docker/blynk-server.service /etc/systemd/system/blynk.service
sudo systemctl daemon-reload
sudo systemctl enable blynk
sudo systemctl start blynk
```

### Log Rotation

Create `/etc/logrotate.d/blynk`:
```
/opt/blynk/logs/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

---

## Configuration

### server.properties — Key Settings

```properties
# Ports
hardware.mqtt.port=8440
https.port=9443
http.port=8084

# Let's Encrypt (place cert symlinks in server working directory)
server.ssl.cert=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
server.ssl.key=/etc/letsencrypt/live/yourdomain.com/privkey.pem

# Force TLS 1.2/1.3 only
latest.tls=true

# Data paths (use absolute paths)
data.folder=/opt/blynk/data
logs.folder=/opt/blynk/logs

# Restrict admin panel to local network only
allowed.administrator.ips=192.168.1.0/24,127.0.0.1/32,0:0:0:0:0:0:0:1/128

# Hardware idle timeout (seconds)
hard.socket.idle.timeout=60

# Admin account (only used on first startup to create the account)
admin.email=your@email.com
admin.pass=YourStrongPasswordHere

# Async logger ring buffer
async.logger.ring.buffer.size=2048
```

### Let's Encrypt — Symlinking Certificates

Blynk looks for cert files in its **working directory**. Symlink your Let's Encrypt certs:

```bash
sudo ln -sf /etc/letsencrypt/live/yourdomain.com/fullchain.pem /opt/blynk/fullchain.crt
sudo ln -sf /etc/letsencrypt/live/yourdomain.com/privkey.pem /opt/blynk/privkey.pem
```

### Gmail Email Setup

Gmail disabled plain-password SMTP login in 2022. You must use a **Gmail App Password**:

1. Enable 2-Step Verification on your Google account
2. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Create an App Password for "Mail"
4. Create `mail.properties` in the same folder as the JAR:

```properties
mail.smtp.auth=true
mail.smtp.starttls.enable=true
mail.smtp.starttls.required=true
mail.smtp.host=smtp.gmail.com
mail.smtp.port=587
mail.smtp.username=your@gmail.com
mail.smtp.password=yoursixteencharapppassword
mail.smtp.ssl.trust=smtp.gmail.com
mail.smtp.ssl.protocols=TLSv1.2 TLSv1.3
mail.smtp.connectiontimeout=10000
mail.smtp.timeout=30000
mail.smtp.writetimeout=30000
```

### Docker

```bash
# Build
docker build -t blynk-server server/Docker/

# Run
docker run --name blynk \
  -v /opt/blynk:/data \
  -p 8440:8440 \
  -p 8084:8080 \
  -p 9443:9443 \
  -e ADMIN_EMAIL=your@email.com \
  -e ADMIN_PASS=YourStrongPassword \
  -d blynk-server
```

---

## Admin Panel

Access at `https://yourserver:9443/admin`

- Log in with the `admin.email` and `admin.pass` from `server.properties`
- The admin password is hashed using SHA-256 on first account creation
- To reset the password: stop the server, delete the `.user` file from the data folder, update `server.properties`, restart — the account will be recreated
- **Important:** keep a backup of your `.user` file as it contains your dashboard configuration

---

## Connecting Hardware (ESP8266 / NodeMCU)

```cpp
#define BLYNK_TEMPLATE_ID ""
#define BLYNK_AUTH_TOKEN  "your-32-char-token"

#include <ESP8266WiFi.h>
#include <BlynkSimpleEsp8266_SSL.h>

char ssid[] = "YourWiFi";
char pass[] = "YourPassword";

void setup() {
    Blynk.begin(BLYNK_AUTH_TOKEN, ssid, pass,
                "yourdomain.com", 9443);  // SSL port
}

void loop() {
    Blynk.run();
}
```

Get your auth token by pressing the **Email** button in the Blynk app device settings.

---

## Protocol Reference

Blynk uses a compact binary protocol optimised for IoT.

**Hardware ↔ Server:**

| Command | Message ID | Length | Body |
|:---:|:---:|:---:|:---:|
| 1 byte | 2 bytes | 2 bytes | Variable |

**App ↔ Server:**

| Command | Message ID | Length | Body |
|:---:|:---:|:---:|:---:|
| 1 byte | 2 bytes | 4 bytes | Variable |

Message ID and Length are big-endian. Full command and response code definitions are in the original source.

---

## License

[GNU GPL](https://github.com/blynkkk/blynk-server/blob/master/license.txt) — same as the original Blynk Server project.
