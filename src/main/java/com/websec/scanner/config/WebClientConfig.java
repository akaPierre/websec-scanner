package com.websec.scanner.config;

import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Configuration
public class WebClientConfig {
    
    @Bean
    public WebClient webClient(ScannerConfig config) throws SSLException {

        SslContext sslContext = SslContextBuilder
                .forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        HttpClient httpClient = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, config.getHttpTimeoutMs())
                .responseTimeout(Duration.ofMillis(config.getHttpTimeoutMs()))
                .doOnConnected(conn -> conn
                            .addHandlerLast(new ReadTimeoutHandler(config.getHttpTimeoutMs(), TimeUnit.MILLISECONDS))
                            .addHandlerLast(new WriteTimeoutHandler(config.getHttpTimeoutMs(), TimeUnit.MILLISECONDS))
                )
                .secure(spec -> spec.sslContext(sslContext))
                .followRedirect(false);

        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .defaultHeader("User-Agent", config.getUserAgent())
                .build();
    }
}