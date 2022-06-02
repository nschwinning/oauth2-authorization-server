package com.example.oauth2authorizationserver.properties;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties(prefix = "com.eon.config.oauth")
public class OAuthProperties {

    private int expirationInSeconds;
    private String app;
    private String issuer;
    private List<RegisteredClient> clients;

    @Getter
    @Setter
    public static class RegisteredClient {

        private String id;
        private String name;
        private String clientId;
        private String clientSecret;

    }

}


