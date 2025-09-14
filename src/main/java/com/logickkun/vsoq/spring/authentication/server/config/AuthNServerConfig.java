package com.logickkun.vsoq.spring.authentication.server.config;

import com.logickkun.vsoq.spring.authentication.server.util.Jwks;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthNServerConfig {

    @Value("${bff.oauth.web.redirect-uri}")
    private String redirectUri;

    // --- Registered Client (BFF, Confidential + PKCE) -------------------------------
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient rc = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("vsoq-bff-web-client")
                .clientSecret(passwordEncoder().encode("vsoq-bff-web-secret"))  // 저장은 인코딩
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // ★ POST 방식 허용
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/bff/web/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(true)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(rc);
    }

    // --- JWK Source
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        return Jwks.generateRsa();
    }

    // -- JWT Decoder
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // --- Password Encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // --- Authentication Provider
    @Bean
    public AuthenticationProvider daoAuthProvider(UserDetailsService uds, PasswordEncoder pe) {
        DaoAuthenticationProvider dao =  new DaoAuthenticationProvider(uds);
        dao.setPasswordEncoder(pe);
        return dao;
    }

}
