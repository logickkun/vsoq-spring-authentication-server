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
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
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

        // Token Settings
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(15))   // Access Token 15분
                .refreshTokenTimeToLive(Duration.ofDays(30))     // Refresh Token 30일
                .reuseRefreshTokens(false)                       // RT 회전(재사용 금지)
                .build();

        // Client Settings
        ClientSettings clientSettings = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(false)
                .build();

        RegisteredClient bff = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("vsoq-bff-web-client")
                .clientSecret(passwordEncoder().encode("vsoq-bff-web-secret"))        // 저장은 인코딩
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)       // ★ POST 방식 허용
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();

        // 예시: InMemory. 운영에선 JdbcRegisteredClientRepository 권장.
        return new InMemoryRegisteredClientRepository(bff);
        // JDBC 사용 시:
        // JdbcRegisteredClientRepository repo = new JdbcRegisteredClientRepository(jdbcTemplate);
        // repo.save(bff); // 최초 1회 저장(이미 있으면 업데이트 로직 별도)
        // return repo;
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
        var d = (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
        // 접두사 없는 과거 $2a$… bcrypt도 임시 허용하려면
        d.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder(12));
        return d;
    }

    // --- Authentication Provider
    @Bean
    public AuthenticationProvider daoAuthProvider(UserDetailsService uds, PasswordEncoder pe) {
        DaoAuthenticationProvider dao =  new DaoAuthenticationProvider(uds);
        dao.setPasswordEncoder(pe);
        return dao;
    }

}
