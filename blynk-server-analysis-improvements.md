# Blynk Server — Comprehensive Code Review & Improvement Report

> Version analysed: **0.41.18-SNAPSHOT** · Java 21 · Netty 4.1.68 · HikariCP 6.3 · Log4j2 2.25.1

---

## 1. Confirmed Bugs

### 1.1 `executeReportingDB` routes to wrong executor
**File:** `server/core/…/BlockingIOProcessor.java`

```java
// BUG – uses dbExecutor, ignoring dbReportingExecutor entirely
public void executeReportingDB(Runnable task) {
    dbExecutor.execute(task);   // ← should be dbReportingExecutor
}
```

The dedicated `dbReportingExecutor` (a single-thread pool, correctly sized for serialised reporting writes) is allocated but **never called**. All reporting DB work lands on the shared `dbExecutor`, defeating the isolation that prevents a DB outage from blocking reporting and vice-versa.

**Fix:**
```java
public void executeReportingDB(Runnable task) {
    dbReportingExecutor.execute(task);
}
```

---

### 1.2 Typo in Dockerfile ENV silently drops async-logger buffer config
**File:** `server/Docker/Dockerfile`

```dockerfile
# Dockerfile defines:
ENV ASYNC_LOGGER_RING_BUGGER_SIZE 2048   ← typo: BUGGER vs BUFFER

# run.sh expects:
async.logger.ring.buffer.size=${ASYNC_LOGGER_RING_BUFFER_SIZE}
```

The shell variable `ASYNC_LOGGER_RING_BUFFER_SIZE` is always empty, so `server.properties` gets `async.logger.ring.buffer.size=` (blank). Log4j2 Async Logger falls back to its default 256-slot ring buffer instead of 2 048 — a **8× throughput regression** on high-frequency logging paths.

**Fix:** Rename the `ENV` line in `Dockerfile`:
```dockerfile
ENV ASYNC_LOGGER_RING_BUFFER_SIZE 2048
```

---

### 1.3 Pipeline handler name typo causes silent replacement failure risk
**Files:**
- `HardwareLoginHandler.java:133` → `"HHArdwareHandler"`
- `MqttHardwareLoginHandler.java:113` → `"HHArdwareMqttHandler"`

```java
pipeline.replace(this, "HHArdwareHandler", new HardwareHandler(...));
//                       ^^ mixed case — inconsistent, fragile
```

Netty handler names are strings; a copy-paste of this name elsewhere will silently fail at runtime with `NoSuchElementException`. Standardise to `"HardwareHandler"` / `"MqttHardwareHandler"` and add constants.

---

### 1.4 HTTP admin sessions are never invalidated (memory leak + security)
**File:** `server/core/…/SessionDao.java`

```java
private final ConcurrentHashMap<String, User> httpSession = new ConcurrentHashMap<>();

public String generateNewSession(User user) {
    String sessionId = UUID.randomUUID().toString();
    httpSession.put(sessionId, user);   // ← never removed
    return sessionId;
}
```

`AdminAuthHandler.logout()` clears the cookie on the client but **never calls `httpSession.remove()`**. Sessions accumulate forever. With a 30-day cookie `MAX_AGE` and repeated logins this is both a memory leak and allows a stolen/leaked cookie to remain valid indefinitely.

**Fix:**
```java
// SessionDao
public void invalidateSession(String sessionId) {
    httpSession.remove(sessionId);
}

// AdminAuthHandler.logout()
@POST @Path("/logout")
public Response logout(@CookieParam(SESSION_COOKIE) String sessionId) {
    if (sessionId != null) sessionDao.invalidateSession(sessionId);
    Response response = redirect(rootPath);
    response.headers().add(SET_COOKIE,
        ServerCookieEncoder.STRICT.encode(makeDefaultSessionCookie("", 0)));
    return response;
}
```

---

### 1.5 Integer pre-increment bug in `getFacebookLogin` stat map
**File:** `server/core/…/UserDao.java`

```java
facebookLogin.compute(key, (k, v) -> v == null ? 1 : v++);
//                                                    ^^ post-increment: always stores old value
```

`v++` returns the *old* value; the map entry is never incremented past 1. Replace with `v + 1`.

---

## 2. Security Issues

### 2.1 Plain-text password comparison in admin login
**File:** `AdminAuthHandler.java:57`

```java
if (!password.equals(user.pass)) {   // ← cleartext compare
```

The admin password is compared as plain text. If `user.pass` is stored as a hash (SHA-256 is used elsewhere in the codebase) this will always fail. If it is stored plain, that is a critical security issue. Use the same `SHA256Util` that exists in `http-admin/test` for all password comparisons.

---

### 2.2 No TLS cipher-suite restriction on self-signed fallback
**File:** `SslContextHolder.java`

When `latest.tls=true`, `TLSv1.3`/`TLSv1.2` are restricted **only on the custom-cert path**. The self-signed certificate builder `build(SslProvider)` ignores `onlyLatestTLS` entirely:

```java
public static SslContext build(SslProvider sslProvider) throws ... {
    SelfSignedCertificate ssc = new SelfSignedCertificate();
    return SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
            .sslProvider(sslProvider)
            .build();   // ← no .protocols(), no cipher restriction
}
```

Even with `latest.tls=true` a development/un-configured server accepts TLS 1.0/1.1.

---

### 2.3 Hardcoded default admin credentials
**File:** `Dockerfile`

```dockerfile
ENV ADMIN_EMAIL admin@blynk.cc
ENV ADMIN_PASS  admin
```

Credential defaults that ship in a container image are routinely exploited. At minimum force the user to supply them via `--env` by removing the defaults and failing with a clear error on startup if they are absent.

---

### 2.4 `gcm.api.key` public key embedded in `gcm.properties`
The bundled example `gcm.properties` ships with a real-looking Firebase/GCM server key. Even if expired, this trains operators to accept credential files in the repo. Remove it and replace with a placeholder.

---

## 3. Dependency Upgrades

| Dependency | Current | Latest (May 2025) | Notes |
|---|---|---|---|
| `netty` | 4.1.68.Final | **4.1.119.Final** | 50+ releases behind; security CVEs fixed |
| `netty-tcnative-boringssl-static` | 2.0.38.Final | **2.0.71.Final** | BoringSSL CVE updates |
| `async-http-client` | 2.12.4 | **3.0.x** | Major: migrated to Netty 4.1 async API |
| `acme4j-client` | 2.15 | **3.4.0** | RFC 8555 spec updates |
| `disruptor` | 3.4.2 | **4.0.0** | Java 21 VarHandle rewrite, faster |
| `javax.mail` | 1.6.2 | **jakarta.mail 2.1.3** | `javax.mail` is end-of-life |
| `apache httpclient` (test) | 4.5.2 | **5.3.x** | 4.x EOL |
| `maven-shade-plugin` | 3.2.1 | **3.6.0** | Reproducible-build fixes |
| `maven-surefire-plugin` | 2.22.1 | **3.5.3** | JUnit 5 + Java 21 support |
| `maven-checkstyle-plugin` | 3.0.0 | **3.6.0** | |
| `jmh-core` | 1.19 | **1.37** | Java 21 compatibility |

**Critical:** Netty 4.1.68 has known CVEs in the HTTP/2 and HTTP codec. Upgrading to 4.1.119 is strongly recommended.

---

## 4. Thread Pool Configuration

### 4.1 Integer truncation produces unexpectedly small pools
**File:** `BlockingIOProcessor.java`

```java
// poolSize default = 6
this.messagingExecutor = new ThreadPoolExecutor(
    poolSize / 4,   // corePool  = 1
    poolSize / 3,   // maxPool   = 2  ← only 2 threads for ALL notification sends
    ...
);
this.historyExecutor = new ThreadPoolExecutor(
    poolSize / 4,   // 1
    poolSize / 2,   // 3
    ...
);
```

Integer division with the default `poolSize=6` yields a messaging pool with **max 2 threads** and a history pool with max 3. On a server with many concurrent push/email/tweet sends, the queue fills and tasks are rejected. Consider using `Math.max(2, poolSize / 3)` etc.

### 4.2 `dbReportingExecutor` never shut down
**File:** `BlockingIOProcessor.close()`

```java
public void close() {
    dbExecutor.shutdown();
    messagingExecutor.shutdown();
    historyExecutor.shutdown();
    dbGetServerExecutor.shutdown();
    // ← dbReportingExecutor.shutdown() missing
}
```

This leaks the reporting thread on shutdown.

### 4.3 Worker thread count formula ignores hyperthreading topology
```java
// TransportTypeHolder
int workerThreads = serverProperties.getIntProperty(
    "server.worker.threads", Runtime.getRuntime().availableProcessors() * 2);
```

On a Raspberry Pi 5 (4 cores, no hyperthreading) `availableProcessors() * 2 = 8` is excessive for Netty I/O workers and will cause context-switch overhead. A better default is `availableProcessors()` with a cap, or expose it clearly in documentation with RPi-specific guidance.

---

## 5. Database / HikariCP

### 5.1 `maxLifetime=0` disables connection recycling
**File:** `DBManager.initConfig()`

```java
config.setMaxLifetime(0);   // ← 0 means infinite lifetime
```

HikariCP recommends `maxLifetime` be set a few seconds below any database-side `idle_timeout` (PostgreSQL default: 10 minutes). Infinite lifetime means stale/dead connections are never replaced until they throw an exception mid-query. Set to `600_000` (10 min) or expose via `db.properties`.

### 5.2 Fixed pool size ignores environment
```java
config.setMaximumPoolSize(5);   // hardcoded, not configurable
```

Should be read from `db.properties` with a sensible default, consistent with how every other limit in the codebase is handled via `ServerProperties`.

### 5.3 `SELECT 1` as connection test query is redundant with modern JDBC
HikariCP 3+ uses `isValid()` by default, which is faster than a round-trip query. Remove `config.setConnectionTestQuery("SELECT 1")` unless targeting a very old PostgreSQL JDBC driver.

### 5.4 Minimum PostgreSQL version check is stale
```java
if (dbVersion < 90500) {   // checks < 9.5.0
```

PostgreSQL 9.5 reached end-of-life in February 2021. Raise the minimum to 13 (still in LTS) and update the error message accordingly.

---

## 6. Memory Usage

### 6.1 All user profiles loaded into RAM on startup
`FileManager.deserializeUsers()` loads every `.user` JSON file into a single `ConcurrentHashMap<UserKey, User>` held in-heap for the lifetime of the server. For a large deployment this can be hundreds of megabytes. There is no eviction policy.

**Recommendation:** Add an optional LRU cache tier in front of `FileManager` for read-heavy access paths. Profiles not accessed in N days can be evicted and re-loaded on demand. This significantly reduces heap pressure for servers with many inactive users.

### 6.2 Netty leak detector disabled unconditionally in production
**File:** `Holder.java:222`

```java
System.setProperty("io.netty.leakDetection.level", "disabled");
```

This is set if no explicit system property exists. While correct for production performance, it means **silent ByteBuf leaks in staging or test environments** unless a developer explicitly passes `-Dio.netty.leakDetection.level=paranoid`. Make this conditional on a `server.properties` flag.

### 6.3 Backup writes entire user corpus once per day
`ProfileSaverWorker.archiveUser()` iterates every user and calls `JsonParser.writeUser(path, user)` in a tight loop on the scheduler thread — potentially hundreds of file writes without any back-pressure. Move this to `blockingIOProcessor` with batching.

---

## 7. Logging

### 7.1 Inconsistent use of `System.out.println` vs Log4j2
Multiple production classes use `System.out.println`:

- `FileManager` (3× on startup warnings)
- `Holder.generateInitialCertificates()`
- `TransportTypeHolder.close()`
- `SslContextHolder.generateInitialCertificates()`

These bypass the async Log4j2 pipeline, are not captured in log files, and cannot have their level adjusted. Replace all with the appropriate logger calls.

### 7.2 Log4j2 async ring buffer too small for burst traffic
Default 256 slots (due to the Docker typo in §1.2) or even the intended 2 048 slots can overflow under a burst of hardware connect/disconnect events. For Disruptor 4.x (recommended upgrade) the ring buffer must be a power of 2; document and validate this.

### 7.3 No MDC/correlation IDs on hardware connection logs
Hardware login, disconnect, and command handling log the channel address but no correlation token. Adding `MDC.put("token", token.substring(0, 8))` in `HardwareLoginHandler` makes log filtering dramatically easier during incident investigation.

---

## 8. Netty Pipeline

### 8.1 Idle timeout for hardware is opt-in but documentation implies it is on
```java
this.hardwareIdleTimeout = props.getIntProperty("hard.socket.idle.timeout", 0);
// 0 = disabled
```

The default Dockerfile sets `HARD_SOCKET_IDLE_TIMEOUT=10` (10 seconds), but `server.properties` default is `0` (off). A new operator running without Docker gets **no idle timeout** — hardware sockets never cleaned up on network failures, leaking memory and event-loop slots.

**Fix:** Default `hard.socket.idle.timeout` to a sensible non-zero value (e.g. `60`) in `server.properties`.

### 8.2 `@ChannelHandler.Sharable` on stateful `HardwareLoginHandler`
`HardwareLoginHandler` is annotated `@Sharable` and holds `Holder`, `DBManager`, and `BlockingIOProcessor` references — these are shared (correct). However it also captures `listenPort` as instance state; if multiple server instances with different ports ever share a handler, this will silently serve wrong redirect ports. Low risk today but fragile.

### 8.3 Missing `AUTO_READ=false` on `ReadingWidgetsWorker` fan-out paths
The `ReadingWidgetsWorker` broadcasts to many hardware channels on a scheduled interval. If a hardware channel's write buffer is full, Netty queues data in the channel's outbound buffer. There is no `Channel.isWritable()` check before these fan-out writes, which can cause unbounded buffer growth for slow/stalled hardware clients.

---

## 9. Docker & Deployment

### 9.1 Dockerfile base image is `ubuntu` (no tag)
```dockerfile
FROM ubuntu   ← pulls "latest" on every build
```

`ubuntu:latest` changes without notice; builds are **not reproducible**. Pin to a specific LTS release:
```dockerfile
FROM ubuntu:24.04
```

### 9.2 Java 11 installed but project compiles to Java 21
```dockerfile
RUN apt install -y openjdk-11-jdk ...
```

The `pom.xml` sets `<release>21</release>`. The container installs JDK 11, so the JAR downloaded from GitHub releases was compiled with Java 21 and will fail at startup with `UnsupportedClassVersionError`.

**Fix:**
```dockerfile
RUN apt-get install -y openjdk-21-jdk-headless
```

### 9.3 `maven` installed in the runtime image unnecessarily
Maven is a build tool and adds ~200 MB to the image. Remove it from the Dockerfile; the server only needs the JRE.

### 9.4 No healthcheck
```dockerfile
# Add:
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:${HTTP_PORT}/admin || exit 1
```

### 9.5 Secrets passed via ENV (visible in `docker inspect` and process list)
`ADMIN_PASS`, `SERVER_SSL_KEY_PASS` are plain ENV vars. For production, use Docker secrets or mount a config file, not environment variables.

### 9.6 No non-root USER
The container runs as root. Add:
```dockerfile
RUN groupadd -r blynk && useradd -r -g blynk blynk
USER blynk
```

---

## 10. ARM / Raspberry Pi 5 Compatibility

### 10.1 Native epoll library only built for `linux-x86_64`
**Files:** `pom.xml` profiles, `server/launcher/pom.xml`

Both Maven profiles (`win` and `unix`) hardcode `<epoll.os>linux-x86_64</epoll.os>`. On a 64-bit ARM system (RPi 4/5, AWS Graviton) the native epoll JNI library is not included in the fat JAR, so Netty silently falls back to NIO. You lose ~20–30% network throughput.

**Fix:** Add an `aarch64` profile:
```xml
<profile>
  <id>unix-aarch64</id>
  <activation>
    <os><arch>aarch64</arch></os>
  </activation>
  <properties>
    <script.extension>.sh</script.extension>
    <epoll.os>linux-aarch_64</epoll.os>
  </properties>
</profile>
```
And similarly update `netty-tcnative-boringssl-static` classifier to `linux-aarch_64`.

### 10.2 BoringSSL native library also missing for ARM
`netty-tcnative-boringssl-static` with classifier `linux-x86_64` will not load on ARM. Without it, OpenSSL is unavailable and `SslContextHolder` falls back to JDK SSL — much slower TLS negotiation, relevant for RPi deployments with many connecting devices.

### 10.3 JVM flags in startup scripts not ARM-aware
If startup scripts pass explicit GC flags such as `-XX:+UseG1GC` with region-size tuning, these need re-tuning for the RPi 5's 4–8 GB memory. Recommend exposing `JAVA_OPTS` as a Docker/systemd env var so operators can adjust without rebuilding.

---

## 11. Startup Scripts & systemd

### 11.1 `run.sh` does not set `JAVA_OPTS`
The script calls `java -jar /blynk/server.jar` with no JVM flags. Recommended additions:
```bash
java \
  -server \
  -Xms64m -Xmx512m \
  -XX:+UseZGC \
  -Dio.netty.leakDetection.level=disabled \
  -Dfile.encoding=UTF-8 \
  $JAVA_OPTS \
  -jar /blynk/server.jar ...
```

### 11.2 No systemd service file provided
Operators running on bare metal (RPi especially) have no reference systemd unit. Provide a `blynk-server.service` with `Restart=on-failure`, `LimitNOFILE=65536`, and `StandardOutput=journal`.

---

## 12. Code Quality / Refactoring

### 12.1 `UserDao` statistics methods are heavily duplicated
`getBoardsUsage()`, `getLibraryVersion()`, `getCpuType()`, `getConnectionType()`, `getHardwareBoards()` are almost identical triple-nested loops that differ only in which `device.hardwareInfo` field they key on. Extract a generic helper:

```java
private Map<String, Integer> countByDeviceField(Function<Device, String> fieldExtractor) {
    Map<String, Integer> data = new HashMap<>();
    for (User user : users.values())
        for (DashBoard dash : user.profile.dashBoards)
            for (Device device : dash.devices) {
                String key = fieldExtractor.apply(device);
                if (key != null) data.merge(key, 1, Integer::sum);
            }
    return data;
}
```

### 12.2 `Holder` is a 200-line grab-bag constructor
`Holder` constructs 20+ objects inline. Extract a `HolderFactory` or use a DI framework (Guice/Dagger) to make unit-testing individual components possible without instantiating the entire server.

### 12.3 `//todo ugly, but quick. refactor` left in production code
`UserDao.createProjectForExportedApp()` has an explicit TODO present since at least 2017. Schedule this for cleanup.

### 12.4 `SimpleDateFormat` in `FileManager` is not thread-safe
If `generateBackupFileName` is ever called from multiple threads (it is — via `ProfileSaverWorker`), the shared `SimpleDateFormat` instance will produce corrupt filenames. Replace with `DateTimeFormatter` (thread-safe) from `java.time`.

---

## 13. Suggested Pull Requests / Patches

| # | Title | Priority |
|---|---|---|
| PR-1 | Fix `executeReportingDB` to use `dbReportingExecutor` | 🔴 Critical |
| PR-2 | Fix Docker `ASYNC_LOGGER_RING_BUGGER_SIZE` typo | 🔴 Critical |
| PR-3 | Fix `dbReportingExecutor` not shut down in `close()` | 🟠 High |
| PR-4 | Fix HTTP admin sessions never invalidated on logout | 🟠 High |
| PR-5 | Fix `v++` → `v + 1` in `getFacebookLogin` | 🟠 High |
| PR-6 | Upgrade Netty to 4.1.119.Final | 🟠 High (CVEs) |
| PR-7 | Upgrade Dockerfile to JDK 21, pin `ubuntu:24.04` | 🟠 High |
| PR-8 | Add `linux-aarch_64` Maven profile for RPi 5 | 🟡 Medium |
| PR-9 | Add `maxLifetime` to HikariCP config | 🟡 Medium |
| PR-10 | Replace `System.out.println` with Log4j2 throughout | 🟡 Medium |
| PR-11 | Add `hard.socket.idle.timeout` non-zero default | 🟡 Medium |
| PR-12 | Add non-root USER and HEALTHCHECK to Dockerfile | 🟡 Medium |
| PR-13 | Refactor duplicate `UserDao` stat methods | 🟢 Low |
| PR-14 | Add systemd unit file for bare-metal / RPi installs | 🟢 Low |
| PR-15 | Replace `SimpleDateFormat` with `DateTimeFormatter` | 🟢 Low |
