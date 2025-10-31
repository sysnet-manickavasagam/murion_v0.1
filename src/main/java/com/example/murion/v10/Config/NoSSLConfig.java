package com.example.murion.v10.Config;


import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;

import org.apache.hc.client5.http.io.HttpClientConnectionManager;

import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Configuration
public class NoSSLConfig {

    @Bean
    public RestTemplate restTemplate() throws Exception {

        SSLContextBuilder sslContext = SSLContextBuilder.create()
                .loadTrustMaterial(null, TrustAllStrategy.INSTANCE);

        SSLConnectionSocketFactory socketFactory =
                new SSLConnectionSocketFactory(
                        sslContext.build(),
                        NoopHostnameVerifier.INSTANCE
                );

        HttpClientConnectionManager cm =
                PoolingHttpClientConnectionManagerBuilder.create()
                        .setSSLSocketFactory(socketFactory)
                        .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(cm)
                .build();

        HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory(httpClient);

        requestFactory.setConnectTimeout(30000);
        requestFactory.setReadTimeout(30000);

        return new RestTemplate(requestFactory);
    }
}
