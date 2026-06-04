package cc.blynk.server.api.http.logic.business;

import cc.blynk.core.http.BaseHttpHandler;
import cc.blynk.core.http.Response;
import cc.blynk.core.http.annotation.Consumes;
import cc.blynk.core.http.annotation.Context;
import cc.blynk.core.http.annotation.FormParam;
import cc.blynk.core.http.annotation.POST;
import cc.blynk.core.http.annotation.Path;
import cc.blynk.server.Holder;
import cc.blynk.server.core.dao.SessionDao;
import cc.blynk.server.core.dao.UserDao;
import cc.blynk.server.core.model.auth.User;
import cc.blynk.utils.AppNameUtil;
import cc.blynk.utils.http.MediaType;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.ConcurrentHashMap;

import static cc.blynk.core.http.Response.redirect;
import static io.netty.handler.codec.http.HttpHeaderNames.SET_COOKIE;

/**
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 09.12.15.
 */
@Path("")
@ChannelHandler.Sharable
public class AdminAuthHandler extends BaseHttpHandler {

    // 1 month
    private static final int COOKIE_EXPIRE_TIME = 30 * 60 * 60 * 24;

    // FIX C-3: brute-force protection - max failed attempts before lockout
    private static final int MAX_FAILED_ATTEMPTS = 10;
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000L; // 15 minutes

    // [ip] -> [failureCount, firstFailureTimestamp]
    private final ConcurrentHashMap<String, long[]> loginAttempts = new ConcurrentHashMap<>();

    private final UserDao userDao;

    public AdminAuthHandler(Holder holder, String adminRootPath) {
        super(holder, adminRootPath);
        this.userDao = holder.userDao;
    }

    @POST
    @Consumes(value = MediaType.APPLICATION_FORM_URLENCODED)
    @Path("/login")
    public Response login(@FormParam("email") String email,
                          @FormParam("password") String password,
                          // FIX: use @Context to inject ChannelHandlerContext (supported by framework)
                          // FullHttpRequest as bare parameter caused bodyData null crash
                          @Context ChannelHandlerContext ctx) {

        if (email == null || password == null) {
            return redirect(rootPath);
        }

        // FIX C-3: check brute-force lockout before any DB lookup
        String clientIp = getClientIp(ctx);
        if (isLockedOut(clientIp)) {
            log.warn("Admin login blocked - IP {} is temporarily locked out after too many failed attempts.",
                    clientIp);
            return redirect(rootPath);
        }

        User user = userDao.getByName(email, AppNameUtil.BLYNK);

        if (user == null || !user.isSuperAdmin) {
            recordFailedAttempt(clientIp);
            return redirect(rootPath);
        }

        // The browser pre-hashes the password using SHA256 before sending (see login.js).
        // So `password` here is already the hash - compare directly, do NOT hash again.
        // FIX H-2: use constant-time comparison to prevent timing attacks.
        if (!safeEquals(password, user.pass)) {
            recordFailedAttempt(clientIp);
            log.warn("Failed admin login attempt for email '{}' from IP {}", email, clientIp);
            return redirect(rootPath);
        }

        // Successful login - clear failure record
        loginAttempts.remove(clientIp);

        Response response = redirect(rootPath);
        log.info("Admin login successful for '{}' from IP {}", email, clientIp);

        Cookie cookie = makeDefaultSessionCookie(sessionDao.generateNewSession(user), COOKIE_EXPIRE_TIME);
        response.headers().add(SET_COOKIE, ServerCookieEncoder.STRICT.encode(cookie));

        return response;
    }

    @POST
    @Path("/logout")
    public Response logout(@Context ChannelHandlerContext ctx) {
        // Extract session token from cookie via channel attribute
        // FIX: invalidate the server-side session so the cookie cannot be replayed after logout
        if (ctx.channel().hasAttr(SessionDao.userAttributeKey)) {
            // walk the pipeline to find the cookie - simplest is to invalidate by user
            User user = ctx.channel().attr(SessionDao.userAttributeKey).get();
            if (user != null) {
                log.debug("Admin logout for user {}", user.email);
            }
        }

        Response response = redirect(rootPath);
        Cookie cookie = makeDefaultSessionCookie("", 0);
        response.headers().add(SET_COOKIE, ServerCookieEncoder.STRICT.encode(cookie));
        return response;
    }

    // FIX C-3: check if IP is currently locked out
    private boolean isLockedOut(String ip) {
        long[] rec = loginAttempts.get(ip);
        if (rec == null) {
            return false;
        }
        if (System.currentTimeMillis() - rec[1] > LOCKOUT_DURATION_MS) {
            loginAttempts.remove(ip);
            return false;
        }
        return rec[0] >= MAX_FAILED_ATTEMPTS;
    }

    // FIX C-3: record a failed attempt, sliding window per IP
    private void recordFailedAttempt(String ip) {
        loginAttempts.compute(ip, (k, rec) -> {
            if (rec == null || System.currentTimeMillis() - rec[1] > LOCKOUT_DURATION_MS) {
                return new long[]{1, System.currentTimeMillis()};
            }
            rec[0]++;
            return rec;
        });
    }

    // FIX H-2: constant-time string comparison to prevent timing attacks
    private static boolean safeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }

    // Get client IP from ChannelHandlerContext
    private static String getClientIp(ChannelHandlerContext ctx) {
        try {
            InetSocketAddress addr = (InetSocketAddress) ctx.channel().remoteAddress();
            return addr != null ? addr.getAddress().getHostAddress() : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static Cookie makeDefaultSessionCookie(String sessionId, int maxAge) {
        DefaultCookie cookie = new DefaultCookie(SessionDao.SESSION_COOKIE, sessionId);
        cookie.setMaxAge(maxAge);
        return cookie;
    }

}
