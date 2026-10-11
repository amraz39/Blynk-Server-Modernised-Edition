# Blynk Community Server — Java 21 / Raspberry Pi 5 Edition

Current server line: **0.41.18-SNAPSHOT**
Runtime: **Java 21**
Deployment target: **Raspberry Pi 5 / ARM64**
Deployable artifact: `server/OUTPUT_TO_USE---ARM64/server-0.41.18-java21.jar`

This repository is a maintained fork of the discontinued open-source Blynk Local Server. It supports legacy Blynk 0.6.1 clients used by ESP8266 and ESP32 devices and is not affiliated with Blynk Inc.

- Original project: <https://github.com/blynkkk/blynk-server>
- License: GNU GPL-3.0

## Why this fork exists

The original server predates Java 21 and current Netty releases. This fork modernizes the runtime and hardens the old server while preserving legacy protocol compatibility.

The latest stability work was driven by ESP32 field traces in which:

- an established hardware connection stopped receiving responses;
- new TCP/login attempts could also stall;
- coherent HTTP uploads failed in the same period;
- the Pi process remained alive;
- the ESP8266 client was less affected because it did not generate the same string-history and coherent-record workload.

The solution is not simply a larger Java heap. The current server prevents event-loop blocking, bounds text-history storage work, keeps PING behavior explicit, updates the network stack, and uses a measured Java 21 service configuration.

## Current stability and performance changes

### Coherent ESP32 telemetry endpoint

The server adds:

```http
PUT /{token}/telemetry/coherent
Content-Type: application/json

["<V61 value>","<V62 value>"]
```

The endpoint:

- requires exactly two non-null string values;
- validates the legacy hardware token;
- stores V61 and V62 under the same server timestamp;
- updates the active application session;
- does **not** echo the large values back onto the device's Blynk hardware socket;
- returns `200 OK` with `Connection: keep-alive` when the request is valid.

This prevents the bulk string records from competing with Blynk login, control and PING traffic on the persistent hardware connection.

### Asynchronous bounded text history

The previous custom string-history implementation appended every incoming value directly from a Netty event-loop thread. Slow filesystem I/O could therefore delay unrelated hardware processing, including PING and login responses.

`TextHistoryProcessor` now:

- accepts only genuinely nonnumeric values; normal numeric reporting remains on the existing binary/aggregate path;
- queues records without blocking the Netty event loop;
- uses a bounded `ArrayBlockingQueue`;
- batches records by destination file on a dedicated daemon writer;
- sanitizes CR/LF and limits one value to 4096 characters;
- rotates each text-history file at 16 MiB to `.1`;
- reports dropped records and write failures at a rate-limited interval;
- drains the queue during orderly server shutdown, with a bounded close timeout.

Current defaults, also set explicitly by `blynk.service`:

| Property | Default |
|---|---:|
| `blynk.text.history.queue.capacity` | 2048 records |
| `blynk.text.history.batch.size` | 512 records |
| `blynk.text.history.flush.interval.ms` | 250 ms |
| `blynk.text.history.file.max.bytes` | 16,777,216 bytes |

String histories remain compatible with the existing `history_<dash>_<device>_V<pin>_text.txt` reader.

### PING backpressure handling

`PingLogic` no longer silently discards a protocol PING when a Netty channel is non-writable. It closes the unhealthy session instead. A client then receives an immediate TCP failure and can establish a clean connection rather than waiting through an ambiguous silent heartbeat timeout.

### Heartbeat timeout correction

When a device supplies `h-beat`, the hardware pipeline now always replaces its read-idle timeout with the calculated device heartbeat deadline. The former comparison against the server-wide idle limit could leave an incorrect handler timeout in place.

The server property default remains:

```properties
hard.socket.idle.timeout=60
```

This does not replace the per-device heartbeat-derived timeout after login.

### Atomic user-profile persistence

User/dashboard profile updates are serialized to a sibling temporary file and then atomically moved over the previous profile. If the filesystem does not support an atomic move, the code falls back to a replace move. A JVM or storage failure can no longer truncate the only valid user profile before serialization completes.

### Protocol exception visibility

Hardware internal-message processing is guarded and logs the complete exception. A malformed internal command no longer disappears without evidence or escapes the handler without context.

### Updated Java 21 network dependencies

The old Netty 4.1.68 line predates Java 21. The current build uses:

| Dependency | Current version |
|---|---:|
| Netty | 4.1.139.Final |
| netty-tcnative BoringSSL | 2.0.76.Final |

The ARM64 build includes the appropriate native libraries for Raspberry Pi 5. Existing ESP8266 protocol behavior is retained; the changes above are server-side and do not require an ESP8266 firmware update.

## Other retained fork improvements

The repository also retains earlier fixes and hardening, including:

- correct reporting-DB executor routing and shutdown;
- bounded Netty outbound watermarks, TCP_NODELAY and connection backlog;
- scheduler/future cleanup and blocking-I/O separation;
- modern date/time handling and HikariCP lifetime/pool configuration;
- SSRF, path-traversal, upload, deserialization and authentication protections;
- TLS 1.2/1.3 mode and corrected admin-panel behavior;
- Gmail App Password support and bounded SMTP timeouts;
- non-root Docker support and ARM64 native transport packaging;
- Java 21 compilation and module compatibility updates.

## Requirements

| Component | Required/recommended |
|---|---|
| Java | OpenJDK/Temurin 21 |
| Maven | 3.8 or newer |
| Pi architecture | ARM64/aarch64 |
| Production working directory | `/opt/blynk` |
| Hardware TCP / HTTP API | configured by `server.properties`; this deployment uses port 8084 |

## Build and test

Confirm Java and Maven first:

```bash
java -version
mvn -version
```

Build the Raspberry Pi 5 artifact **without skipping tests**:

```bash
mvn clean package "-Depoll.os=linux-aarch_64"
```

The launcher JAR is produced at:

```text
server/launcher/target/server-0.41.18-SNAPSHOT.jar
```

Copy the verified build to the deployment-output name:

```powershell
Copy-Item -LiteralPath .\server\launcher\target\server-0.41.18-SNAPSHOT.jar `
  -Destination .\server\OUTPUT_TO_USE---ARM64\server-0.41.18-java21.jar
```

Important targeted coverage includes:

- 100 keep-alive coherent V61/V62 updates followed by exact value checks;
- PING handling on writable and non-writable channels;
- text-history queueing, batching, sanitization, overflow and close behavior;
- existing module unit tests and checkstyle rules.

Do not document or distribute a JAR produced with `-DskipTests` as the validated deployment artifact.

## Production Java 21 service

The deployment uses the repository-root `blynk.service`, not the older generic `server/Docker/blynk-server.service`.

Important current settings:

| Setting | Current value | Reason |
|---|---:|---|
| `MALLOC_ARENA_MAX` | 1 | prevents per-thread glibc arena retention from inflating RSS |
| `-Xms` / `-Xmx` | 384 MiB / 384 MiB | fixed, right-sized heap; the workload did not justify a continually increasing heap |
| Collector | generational ZGC | low-pause Java 21 collection for Netty event-loop responsiveness |
| `AlwaysPreTouch` | enabled | commits heap pages at startup instead of faulting them during traffic |
| `ZUncommit` | disabled | keeps the fixed heap resident and avoids commit/uncommit latency |
| Worker threads | 4 | matches the Pi 5 workload without unnecessary thread/arena growth |
| Netty allocator | pooled | bounds direct-buffer churn |
| `MemoryHigh` | 768 MiB | stays above normal RSS; avoids routine synchronous cgroup reclaim |
| `MemoryMax` | 1 GiB | hard safety ceiling with native/direct-buffer headroom |
| `MemorySwapMax` | 0 | avoids minute-long live stalls caused by swap/reclaim |
| `TasksMax` | 128 | bounds process/thread count |
| `Nice` | 0 | normal priority for latency-sensitive event loops |

The Java heap is not the same as process RSS. A service using a fixed 384 MiB heap can legitimately show roughly 500 MiB RSS after pre-touch, native Netty buffers, code cache, metaspace and thread stacks. Do not raise `-Xmx` merely because RSS exceeds 384 MiB. Investigate heap, native memory and cgroup accounting separately.

Current JVM command excerpt:

```ini
[Unit]
Description=Blynk Server
After=network-online.target
Wants=network-online.target

StartLimitIntervalSec=120
StartLimitBurst=5
StartLimitAction=none

[Service]
Type=simple
User=*****
WorkingDirectory=/opt/blynk


Environment="MALLOC_ARENA_MAX=1"

ExecStart=/usr/bin/java \
    -server \
    -Xms384m \
    -Xmx384m \
    -Xss512k \
    -XX:+UseZGC \
    -XX:+ZGenerational \
    -XX:+AlwaysPreTouch \
    -XX:-ZUncommit \
    -XX:+ExitOnOutOfMemoryError \
    -XX:+HeapDumpOnOutOfMemoryError \
    -XX:HeapDumpPath=/opt/blynk \
    -XX:NativeMemoryTracking=summary \
    -Xlog:gc*,safepoint,os+container=info:file=/opt/blynk/gc.log:time,uptime,level,tags:filecount=5,filesize=10M \
    -Dblynk.text.history.queue.capacity=2048 \
    -Dblynk.text.history.batch.size=512 \
    -Dblynk.text.history.flush.interval.ms=250 \
    -Dblynk.text.history.file.max.bytes=16777216 \
    -Dio.netty.allocator.type=pooled \
    -Djava.security.egd=file:/dev/urandom \
    --add-opens=java.base/java.lang=ALL-UNNAMED \
    -jar /opt/blynk/server-0.41.18-java21.jar \
    -dataFolder /opt/blynk \
    -workerThreads 4

Restart=always
RestartSec=15
TimeoutStopSec=30

StandardOutput=journal
StandardError=journal
SyslogIdentifier=blynk
LogRateLimitIntervalSec=30
LogRateLimitBurst=1000

MemoryHigh=768M
MemoryMax=1G
MemorySwapMax=0

OOMScoreAdjust=200
TasksMax=128

Nice=0

# Hardening.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/blynk
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

The complete resource limits and hardening options are in `blynk.service`.

## Deploy from `/home/shared` on Raspberry Pi 5

The temporary files are expected at:

```text
/home/shared/server-0.41.18-java21.jar
/home/shared/blynk.service
```

First verify them:

```bash
ls -lh /home/shared/server-0.41.18-java21.jar /home/shared/blynk.service
sha256sum /home/shared/server-0.41.18-java21.jar
```

Back up the deployed files before replacement:

```bash
sudo cp -a /opt/blynk/server-0.41.18-java21.jar \
  /opt/blynk/server-0.41.18-java21.jar.pre-update
sudo cp -a /etc/systemd/system/blynk.service \
  /etc/systemd/system/blynk.service.pre-update
```

Install the new files and restart:

```bash
sudo systemctl stop blynk
sudo install -o <user> -g <user> -m 0644 \
  /home/shared/server-0.41.18-java21.jar \
  /opt/blynk/server-0.41.18-java21.jar
sudo install -o root -g root -m 0644 \
  /home/shared/blynk.service \
  /etc/systemd/system/blynk.service
sudo systemctl daemon-reload
sudo systemctl restart blynk
```

Verify the deployed process:

```bash
sudo systemctl status blynk --no-pager
sudo systemctl show blynk \
  -p MainPID -p MemoryCurrent -p MemoryPeak -p MemoryHigh -p MemoryMax
sudo journalctl -u blynk -n 100 --no-pager
```

Expected startup message:

```text
Blynk Server 0.41.18-SNAPSHOT successfully started.
```

Confirm the active JVM flags rather than assuming the unit was reloaded:

```bash
pid=$(systemctl show -p MainPID --value blynk)
sudo tr '\0' ' ' < /proc/$pid/cmdline
```

The command line should contain `-Xms384m`, `-Xmx384m`, `UseZGC`, `ZGenerational`, the text-history properties, the correct JAR path and `-workerThreads 4`.

## Monitoring

Service log:

```bash
sudo journalctl -u blynk -f
```

GC/safepoint/container log:

```bash
tail -f /opt/blynk/gc.log
```

Memory comparison:

```bash
pid=$(systemctl show -p MainPID --value blynk)
ps -o pid,rss,vsz,etime,cmd -p "$pid"
sudo jcmd "$pid" GC.heap_info
sudo jcmd "$pid" VM.native_memory summary
```

Look for:

- long safepoints or GC pauses that overlap device outages;
- `Text-history health` warnings showing queue drops or write failures;
- recurring channel closures caused by non-writable PING responses;
- steady RSS growth that materially diverges from both Java heap and native-memory accounting;
- systemd memory pressure approaching `MemoryHigh`.

## Configuration highlights

Production `server.properties` should include the actual deployment ports and paths. Relevant defaults in this source tree include:

```properties
http.port=8084
hard.socket.idle.timeout=60
log.level=info
```

Keep tokens, administrator credentials and private keys out of version control. Back up the Blynk data folder before server upgrades; user profile files contain dashboards, tokens and application configuration.

## Compatibility

- The standard legacy Blynk TCP protocol remains compatible with existing ESP8266 devices.
- The coherent HTTP endpoint is additive and used by the ESP32 firmware.
- Text history is written only for nonnumeric values; numeric sensors keep the original reporting pipeline.
- The server-side fixes do not require the ESP8266 to use the ESP32's patched client-library macros.

## Key implementation files

```text
server/http-api/.../HttpAPILogic.java
server/core/.../PingLogic.java
server/core/.../ReportingDiskDao.java
server/core/.../reporting/text/TextHistoryProcessor.java
server/core/.../FileManager.java
server/tcp-hardware-server/.../BlynkInternalLogic.java
integration-tests/.../HttpAPIKeepAliveServerTest.java
pom.xml
blynk.service
```

## Change safety

Always back up the current source/document, deployable JAR, `blynk.service` and `/opt/blynk` data before replacement. A service restart alone is sufficient only after the updated JAR/unit is already installed; unit-file changes additionally require `sudo systemctl daemon-reload`.

## License

GNU GPL-3.0, consistent with the original Blynk Server project.
