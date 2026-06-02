package cc.blynk.core.http.handlers;

import cc.blynk.core.http.utils.ContentTypeUtil;
import cc.blynk.utils.FileUtils;
import cc.blynk.utils.properties.ServerProperties;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.DefaultFileRegion;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpChunkedInput;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.stream.ChunkedFile;
import io.netty.util.ReferenceCountUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Pattern;

import static cc.blynk.server.core.protocol.handlers.DefaultExceptionHandler.handleGeneralException;
import static io.netty.handler.codec.http.HttpHeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN;
import static io.netty.handler.codec.http.HttpHeaderNames.CACHE_CONTROL;
import static io.netty.handler.codec.http.HttpHeaderNames.CONNECTION;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_LENGTH;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;
import static io.netty.handler.codec.http.HttpHeaderNames.DATE;
import static io.netty.handler.codec.http.HttpHeaderNames.EXPIRES;
import static io.netty.handler.codec.http.HttpHeaderNames.IF_MODIFIED_SINCE;
import static io.netty.handler.codec.http.HttpHeaderNames.LAST_MODIFIED;
import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_MODIFIED;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;

/**
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 10.12.15.
 */
public class StaticFileHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LogManager.getLogger(StaticFileHandler.class);

    // FIX M-1/P-7: DateTimeFormatter is thread-safe; SimpleDateFormat was not
    private static final DateTimeFormatter HTTP_DATE_FORMATTER =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US)
                             .withZone(ZoneId.of("GMT"));
    private static final int HTTP_CACHE_SECONDS = 60;

    /**
     * Used for case when server started from IDE and static files wasn't unpacked from jar.
     */
    private final boolean isUnpacked;
    private final StaticFile[] staticPaths;
    private final String jarPath;

    public StaticFileHandler(ServerProperties props, StaticFile... staticPaths) {
        this.staticPaths = staticPaths;
        this.isUnpacked = props.isUnpacked;
        this.jarPath = props.jarPath;
    }

    private static void sendError(ChannelHandlerContext ctx, HttpResponseStatus status) {
        FullHttpResponse response = new DefaultFullHttpResponse(
                HTTP_1_1, status, Unpooled.copiedBuffer("Failure: " + status + "\r\n", StandardCharsets.UTF_8));
        response.headers().set(CONTENT_TYPE, "text/plain; charset=UTF-8");

        // Close the connection as soon as the error message is sent.
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    /**
     * When file timestamp is the same as what the browser is sending up, send a "304 Not Modified"
     *
     * @param ctx
     *            Context
     */
    private static void sendNotModified(ChannelHandlerContext ctx) {
        FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, NOT_MODIFIED);
        setDateHeader(response);

        // Close the connection as soon as the error message is sent.
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    /**
     * Sets the Date header for the HTTP response
     *
     * @param response
     *            HTTP response
     */
    private static void setDateHeader(FullHttpResponse response) {
        response.headers().set(DATE, HTTP_DATE_FORMATTER.format(ZonedDateTime.now()));
    }

    /**
     * Sets the Date and Cache headers for the HTTP Response
     *
     * @param response
     *            HTTP response
     * @param fileToCache
     *            file to extract content type
     */
    private static void setDateAndCacheHeaders(io.netty.handler.codec.http.HttpResponse response, File fileToCache) {
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("GMT"));
        ZonedDateTime expires = now.plusSeconds(HTTP_CACHE_SECONDS);
        ZonedDateTime lastModified = ZonedDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(fileToCache.lastModified()), ZoneId.of("GMT"));

        response.headers()
                .set(DATE, HTTP_DATE_FORMATTER.format(now))
                .set(EXPIRES, HTTP_DATE_FORMATTER.format(expires))
                .set(CACHE_CONTROL, "private, max-age=" + HTTP_CACHE_SECONDS)
                .set(LAST_MODIFIED, HTTP_DATE_FORMATTER.format(lastModified));
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!(msg instanceof FullHttpRequest)) {
            return;
        }

        FullHttpRequest req = (FullHttpRequest) msg;

        StaticFile staticFile = getStaticPath(req.uri());
        if (staticFile != null) {
            try {
                serveStatic(ctx, req, staticFile);
            } finally {
                ReferenceCountUtil.release(req);
            }
            return;
        }

        ctx.fireChannelRead(req);
    }

    private StaticFile getStaticPath(String path) {
        for (StaticFile staticPath : staticPaths) {
            if (staticPath.isStatic(path)) {
                return staticPath;
            }
        }
        return null;
    }

    private void serveStatic(ChannelHandlerContext ctx, FullHttpRequest request, StaticFile staticFile)
            throws Exception {
        if (!request.decoderResult().isSuccess()) {
            sendError(ctx, BAD_REQUEST);
            return;
        }

        if (request.method() != HttpMethod.GET) {
            return;
        }

        Path path;
        String uri = request.uri();

        if (isNotSecure(uri)) {
            sendError(ctx, NOT_FOUND);
            return;
        }

        //running from jar
        if (isUnpacked) {
            log.trace("Is unpacked.");
            if (staticFile instanceof StaticFileEdsWith) {
                StaticFileEdsWith staticFileEdsWith = (StaticFileEdsWith) staticFile;
                path = Paths.get(staticFileEdsWith.folderPathForStatic, uri);
                // FIX C-2: canonical path guard - verify resolved path stays inside root
                try {
                    Path root = Paths.get(staticFileEdsWith.folderPathForStatic).toRealPath();
                    Path resolved = path.normalize().toAbsolutePath();
                    if (!resolved.startsWith(root)) {
                        log.warn("Path traversal attempt blocked: '{}'", uri);
                        sendError(ctx, NOT_FOUND);
                        return;
                    }
                } catch (Exception ignored) {
                    // toRealPath throws if file doesn't exist yet; normalize() is sufficient
                    path = path.normalize();
                    Path root = Paths.get(staticFileEdsWith.folderPathForStatic).normalize().toAbsolutePath();
                    if (!path.toAbsolutePath().startsWith(root)) {
                        log.warn("Path traversal attempt blocked: '{}'", uri);
                        sendError(ctx, NOT_FOUND);
                        return;
                    }
                }
            } else {
                path = Paths.get(jarPath, uri).normalize();
                // FIX C-2: canonical path guard for jar-relative paths
                Path root = Paths.get(jarPath).normalize().toAbsolutePath();
                if (!path.toAbsolutePath().startsWith(root)) {
                    log.warn("Path traversal attempt blocked: '{}'", uri);
                    sendError(ctx, NOT_FOUND);
                    return;
                }
            }
        } else {
            //for local mode / running from ide
            path = FileUtils.getPathForLocalRun(uri);
        }

        log.trace("Getting file from path {}", path);

        if (path == null || Files.notExists(path) || Files.isDirectory(path)) {
            sendError(ctx, NOT_FOUND);
            return;
        }

        File file = path.toFile();

        // Cache Validation
        String ifModifiedSince = request.headers().get(IF_MODIFIED_SINCE);
        if (ifModifiedSince != null && !ifModifiedSince.isEmpty() && !(staticFile instanceof NoCacheStaticFile)) {
            try {
                // FIX M-1/P-7: use thread-safe DateTimeFormatter instead of SimpleDateFormat
                long ifModifiedSinceDateSeconds =
                        HTTP_DATE_FORMATTER.parse(ifModifiedSince, java.time.ZonedDateTime::from)
                                           .toEpochSecond();
                long fileLastModifiedSeconds = file.lastModified() / 1000;
                if (ifModifiedSinceDateSeconds == fileLastModifiedSeconds) {
                    sendNotModified(ctx);
                    return;
                }
            } catch (Exception ignored) {
                // Malformed If-Modified-Since header — serve the file normally
            }
        }

        RandomAccessFile raf;
        try {
            raf = new RandomAccessFile(file, "r");
        } catch (FileNotFoundException ignore) {
            sendError(ctx, NOT_FOUND);
            return;
        }
        long fileLength = raf.length();

        HttpResponse response = new DefaultHttpResponse(HTTP_1_1, OK);
        response.headers()
                .set(CONTENT_LENGTH, fileLength)
                .set(CONTENT_TYPE, ContentTypeUtil.getContentType(file.getName()))
                .set(ACCESS_CONTROL_ALLOW_ORIGIN, "*");

        //todo setup caching for files.
        setDateAndCacheHeaders(response, file);
        if (HttpUtil.isKeepAlive(request)) {
            response.headers().set(CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        }

        // Write the initial line and the header.
        ctx.write(response);

        // Write the content.
        ChannelFuture sendFileFuture;
        ChannelFuture lastContentFuture;
        if (ctx.pipeline().get(SslHandler.class) == null) {
            ctx.write(new DefaultFileRegion(raf.getChannel(), 0, fileLength), ctx.newProgressivePromise());
            // Write the end marker.
            lastContentFuture = ctx.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
        } else {
            sendFileFuture =
                    ctx.writeAndFlush(new HttpChunkedInput(new ChunkedFile(raf, 128 * 1024)),
                            ctx.newProgressivePromise());
            // HttpChunkedInput will write the end marker (LastHttpContent) for us.
            lastContentFuture = sendFileFuture;
        }

        // Decide whether to close the connection or not.
        if (!HttpUtil.isKeepAlive(request)) {
            // Close the connection when the whole content is written out.
            lastContentFuture.addListener(ChannelFutureListener.CLOSE);
        }
    }

    private static final Pattern INSECURE_URI = Pattern.compile(".*[<>&\"].*");

    private static boolean isNotSecure(String uri) {
        if (uri.isEmpty() || uri.charAt(0) != '/') {
            return true;
        }

        return uri.contains("/.")
                || uri.contains("./")
                || uri.contains(".\\")
                || uri.contains("\\.")
                || uri.charAt(0) == '.' || uri.charAt(uri.length() - 1) == '.'
                || INSECURE_URI.matcher(uri).matches();

    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (cause.getMessage() != null && cause.getMessage().contains("unknown_ca")) {
            log.warn("Self-generated certificate.");
        } else {
            handleGeneralException(ctx, cause);
        }
    }

}
