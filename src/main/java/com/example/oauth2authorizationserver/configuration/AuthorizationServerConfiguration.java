package com.example.oauth2authorizationserver.configuration;

import com.example.oauth2authorizationserver.properties.OAuthProperties;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@RequiredArgsConstructor
@EnableConfigurationProperties(OAuthProperties.class)
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    private final OAuthProperties oAuthProperties;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        /**
         * Default Endpoints
         * -----------------
         * Token Endpoint       /oauth2/token
         * JWK Set Endpoint     /oauth2/jwks
         */
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.httpBasic(withDefaults()).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        var clients = oAuthProperties.getClients().stream()
                .map(registeredClient -> mapToRegisteredClient(registeredClient))
                .collect(Collectors.toUnmodifiableList());

        return new InMemoryRegisteredClientRepository(clients);
    }

    private RegisteredClient mapToRegisteredClient(OAuthProperties.RegisteredClient client) {
        var secret = "{noop}" + client.getClientSecret();
        return RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientSecret(secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("write")
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer(oAuthProperties.getIssuer())
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {

            //Add custom field to token
            context.getClaims().claim("app", oAuthProperties.getApp());
            var exp = LocalDateTime.now().plusSeconds(oAuthProperties.getExpirationInSeconds())
                    .atZone(ZoneId.systemDefault()).toInstant();
            context.getClaims().expiresAt(exp);

        };
    }

}
