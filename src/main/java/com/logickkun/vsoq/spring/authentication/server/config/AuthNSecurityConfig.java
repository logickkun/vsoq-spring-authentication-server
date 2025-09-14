package com.logickkun.vsoq.spring.authentication.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class AuthNSecurityConfig {

    @Bean
    @Order (1)
    public SecurityFilterChain authNSecurityFilterChain(HttpSecurity http, AuthenticationProvider dao) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, auth2AuthorizationServerConfigurer -> auth2AuthorizationServerConfigurer
                        .oidc(Customizer.withDefaults())
                )
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher())
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                );
        return http.build();
    }


    @Bean
    @Order(2)
    SecurityFilterChain appSecurityFilterChain(HttpSecurity http, AuthenticationProvider dao) throws Exception {
        http
                .csrf(CsrfConfigurer::disable) // 최소화하려면 추후 /login POST만 예외로
                .httpBasic(HttpBasicConfigurer::disable)
                .authenticationProvider(dao)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                // DevTools(F12) Endpoint
                                "/.well-known/**",

                                // Login Form Request Endpoint
                                "/auth/**",

                                //Authorization Server Endpoint
                                "/oauth2/authorize", "/oauth2/token", "/oauth2/revoke", "/oauth2/jwks", "/connect/register", "/connect/userinfo", "/connect/logout",

                                // Static resources
                                "/index.html","/assets/**","/favicon.ico","/vite.svg",

                                // Error Page
                                "/error"

                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/auth/login")                 // Gateway Route ID sas_login_form    -> SAS 인증 서버 로그인 폼 Endpoint
                        .loginProcessingUrl("/web/login")           // Gateway Route ID sas_login_request -> SAS 인증 서버 로그인 요청 Endpoint
                        .permitAll()
                );
        return http.build();
    }

}
