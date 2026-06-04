package cc.blynk.server.core.model.widgets.others.webhook;

import cc.blynk.server.core.model.enums.PinMode;
import cc.blynk.server.core.model.enums.PinType;
import cc.blynk.server.core.model.widgets.OnePinWidget;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 05.09.16.
 */
public class WebHook extends OnePinWidget {

    private static final Logger log = LogManager.getLogger(WebHook.class);

    // FIX C-1: SSRF protection - block loopback, link-local, and private ranges.
    // Set system property "blynk.webhook.allow.local.urls=true" to bypass in tests.
    private static final boolean ALLOW_LOCAL_URLS =
            Boolean.getBoolean("blynk.webhook.allow.local.urls");

    private static final Set<String> BLOCKED_HOSTS = Set.of(
            "localhost", "127.0.0.1", "0.0.0.0", "::1", "ip6-localhost"
    );
    // Matches RFC-1918 private ranges + link-local (169.254.x.x AWS metadata etc.)
    private static final Pattern PRIVATE_IP_PATTERN = Pattern.compile(
            "^(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
            + "|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}"
            + "|192\\.168\\.\\d{1,3}\\.\\d{1,3}"
            + "|169\\.254\\.\\d{1,3}\\.\\d{1,3}"
            + "|100\\.6[4-9]\\.\\d{1,3}\\.\\d{1,3}"  // RFC 6598 CGNAT
            + "|100\\.[7-9]\\d\\.\\d{1,3}\\.\\d{1,3}"
            + "|100\\.1[0-2]\\d\\.\\d{1,3}\\.\\d{1,3}"
            + "|fd[0-9a-fA-F]{2}:.*)$"  // IPv6 ULA
    );

    public String url;

    //GET is always default so we don't do null checks
    public SupportedWebhookMethod method = SupportedWebhookMethod.GET;

    public Header[] headers;

    public String body;

    public transient volatile int failureCounter = 0;

    /**
     * FIX C-1: Validates webhook URL against SSRF attacks.
     * Blocks private/loopback/link-local IPs, non-http schemes, and
     * URL-encoded bypass attempts. Previously only checked startsWith("http").
     */
    public static boolean isValidUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                log.debug("Webhook URL rejected: invalid scheme '{}'", scheme);
                return false;
            }
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            if (!ALLOW_LOCAL_URLS) {
                String hostLower = host.toLowerCase();
                if (BLOCKED_HOSTS.contains(hostLower)) {
                    log.warn("Webhook URL rejected (SSRF): blocked host '{}'", host);
                    return false;
                }
                if (PRIVATE_IP_PATTERN.matcher(hostLower).matches()) {
                    log.warn("Webhook URL rejected (SSRF): private IP range '{}'", host);
                    return false;
                }
            }
            return true;
        } catch (URISyntaxException e) {
            log.debug("Webhook URL rejected: malformed URI '{}'", url);
            return false;
        }
    }

    public boolean isNotFailed(int webhookFailureLimit) {
        return failureCounter < webhookFailureLimit;
    }

    //a bit ugly but as quick fix ok
    public boolean isSameWebHook(int deviceId, short pin, PinType type) {
        return super.isSame(deviceId, pin, type);
    }

    @Override
    public void sendAppSync(Channel appChannel, int dashId, int targetId) {
    }

    @Override
    public void sendHardSync(ChannelHandlerContext ctx, int msgId, int deviceId) {
    }

    @Override
    public boolean updateIfSame(int deviceId, short pin, PinType type, String value) {
        return false;
    }

    @Override
    public boolean isSame(int deviceId, short pin, PinType type) {
        return false;
    }

    @Override
    //supports only virtual pins
    public PinMode getModeType() {
        return null;
    }

    @Override
    public int getPrice() {
        return 500;
    }
}
