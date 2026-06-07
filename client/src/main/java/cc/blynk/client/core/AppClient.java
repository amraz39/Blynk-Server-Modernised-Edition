package cc.blynk.client.core;



import cc.blynk.client.handlers.ClientReplayingMessageDecoder;

import cc.blynk.server.core.protocol.handlers.encoders.MessageEncoder;

import cc.blynk.server.core.stats.GlobalStats;

import cc.blynk.utils.properties.ServerProperties;

import io.netty.channel.ChannelInitializer;

import io.netty.channel.ChannelPipeline;

import io.netty.channel.socket.SocketChannel;

import io.netty.handler.ssl.SslContext;

import io.netty.handler.ssl.SslContextBuilder;

import io.netty.handler.ssl.SslProvider;

import io.netty.handler.ssl.util.InsecureTrustManagerFactory;



import java.io.File;

import java.util.Random;



/**

 * The Blynk Project.

 * Created by Dmitriy Dumanskiy.

 * Created on 11.03.15.

 */

public class AppClient extends BaseClient {



    protected SslContext sslCtx;



    public AppClient(String host, int port) {

        super(host, port, new Random());

    }



    protected AppClient(String host, int port, Random msgIdGenerator, ServerProperties properties) {

        super(host, port, msgIdGenerator, properties);

        log.info("Creating app client. Host {}, sslPort : {}", host, port);



        String serverCertPath = props.getProperty("server.ssl.cert");

        String clientCertPath = props.getProperty("client.ssl.cert");

        String clientKeyPath = props.getProperty("client.ssl.key");



        log.info("SSL cert paths - server: '{}', client: '{}', key: '{}'",

                serverCertPath, clientCertPath, clientKeyPath);



        // If cert paths are empty or null, disable SSL

        if (serverCertPath == null || serverCertPath.isEmpty()

                || clientCertPath == null || clientCertPath.isEmpty()

                || clientKeyPath == null || clientKeyPath.isEmpty()) {

            log.info("SSL certificate paths not configured. SSL will be disabled.");

            this.sslCtx = null;

            return;

        }



        File serverCert = makeCertificateFile("server.ssl.cert");

        File clientCert = makeCertificateFile("client.ssl.cert");

        File clientKey = makeCertificateFile("client.ssl.key");

        log.info("Server cert path: {}, exists: {}", serverCert.getAbsolutePath(), serverCert.exists());

        log.info("Client cert path: {}, exists: {}", clientCert.getAbsolutePath(), clientCert.exists());

        log.info("Client key path: {}, exists: {}", clientKey.getAbsolutePath(), clientKey.exists());

        try {

            if (!serverCert.exists() || !clientCert.exists() || !clientKey.exists()) {

                log.info("Enabling one-way auth with no certs checks.");

                this.sslCtx = SslContextBuilder.forClient().sslProvider(SslProvider.JDK)

                        .trustManager(InsecureTrustManagerFactory.INSTANCE)

                        .build();

            } else {

                log.info("Enabling mutual auth.");

                String clientPass = props.getProperty("client.ssl.key.pass");

                this.sslCtx = SslContextBuilder.forClient()

                        .sslProvider(SslProvider.JDK)

                        .trustManager(serverCert)

                        .keyManager(clientCert, clientKey, clientPass)

                        .build();

            }

        } catch (Exception e) {

            log.error("Error initializing SSL context. Reason : {}. SSL will be disabled.", e.getMessage());

            log.debug(e);

            this.sslCtx = null;

        }

    }



    @Override

    public ChannelInitializer<SocketChannel> getChannelInitializer() {

        return new ChannelInitializer<>() {

            @Override

            public void initChannel(SocketChannel ch) {

                ChannelPipeline pipeline = ch.pipeline();

                if (sslCtx != null) {

                    pipeline.addLast(sslCtx.newHandler(ch.alloc(), host, port));

                }

                pipeline.addLast(new ClientReplayingMessageDecoder());

                pipeline.addLast(new MessageEncoder(new GlobalStats()));

            }

        };

    }

}

