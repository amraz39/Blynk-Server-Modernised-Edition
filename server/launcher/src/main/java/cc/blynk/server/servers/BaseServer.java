package cc.blynk.server.servers;

import cc.blynk.server.transport.TransportTypeHolder;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.ServerChannel;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.socket.SocketChannel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetSocketAddress;

/**
 * Base server abstraction. Class responsible for Netty EventLoops starting amd port listening.
 *
 * The Blynk Project.
 * Created by Dmitriy Dumanskiy.
 * Created on 3/10/2015.
 */
public abstract class BaseServer {

    protected static final Logger log = LogManager.getLogger(BaseServer.class);

    private final String listenAddress;
    protected final int port;
    private final TransportTypeHolder transportTypeHolder;

    private ChannelFuture cf;

    protected BaseServer(String listenAddress, int port, TransportTypeHolder transportTypeHolder) {
        this.listenAddress = listenAddress;
        this.port = port;
        this.transportTypeHolder = transportTypeHolder;
    }

    public BaseServer start() throws Exception {
        buildServerAndRun(
                transportTypeHolder.bossGroup,
                transportTypeHolder.workerGroup,
                transportTypeHolder.channelClass
        );

        return this;
    }

    private void buildServerAndRun(EventLoopGroup bossGroup, EventLoopGroup workerGroup,
                                   Class<? extends ServerChannel> channelClass) throws Exception {

        var b = new ServerBootstrap();
        try {
            b.group(bossGroup, workerGroup)
                    .channel(channelClass)
                    // FIX P-1: was using OS default backlog (50-128); raise to handle
                    // connection storms (e.g. many IoT devices reconnecting after power cycle)
                    .option(ChannelOption.SO_BACKLOG, 1024)
                    .childOption(ChannelOption.SO_KEEPALIVE, true)
                    // FIX M-3: disable Nagle's algorithm - Blynk messages are small and
                    // latency-sensitive; buffering them adds unnecessary delay
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    // FIX M-3: bound the per-channel write buffer to prevent unbounded heap
                    // growth when hardware clients are slow/stalled during fan-out writes
                    .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK,
                            new WriteBufferWaterMark(8 * 1024, 32 * 1024))
                    .childHandler(getChannelInitializer());

            var listenTo = (listenAddress == null || listenAddress.isEmpty())
                    ? new InetSocketAddress(port)
                    : new InetSocketAddress(listenAddress, port);
            this.cf = b.bind(listenTo).sync();
        } catch (Exception e) {
            log.error("Error initializing {}, port {}", getServerName(), port, e);
            throw e;
        }

        log.info("{} server listening at {} port.", getServerName(), port);
    }

    protected abstract ChannelInitializer<SocketChannel> getChannelInitializer();

    protected abstract String getServerName();

    public ChannelFuture close() {
        return cf.channel().close();
    }
}
