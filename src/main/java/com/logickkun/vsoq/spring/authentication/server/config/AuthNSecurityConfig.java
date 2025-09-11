package com.logickkun.vsoq.spring.authentication.server.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;


@Configuration
public class AuthNSecurityConfig {

    @Bean
    @Order (1)
    public SecurityFilterChain authNSecurityFilterChain(HttpSecurity http, AuthenticationProvider dao) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .authenticationProvider(dao)
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authorizationServer ->
                        authorizationServer
                                .oidc(oidc -> oidc
                                .userInfoEndpoint(uie -> uie.
                                        userInfoMapper(uim -> {
                                           String principalName = uim.getAuthorization().getPrincipalName();
                                            return OidcUserInfo.builder()
                                                    .subject(principalName)
                                                    .claim("name", principalName)
                                                    .claim("display_name", principalName)
                                                    .claim("picture", "https://www.gravatar.com/avatar/?d=identicon")
                                                    .build();
                                        }))
                                )
                    ).oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                            new LoginUrlAuthenticationEntryPoint("/login"),
                            new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appChain(HttpSecurity http, AuthenticationProvider dao) throws Exception {
        http
                .authenticationProvider(dao)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/error", "/css/**", "/js/**", "/images/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
