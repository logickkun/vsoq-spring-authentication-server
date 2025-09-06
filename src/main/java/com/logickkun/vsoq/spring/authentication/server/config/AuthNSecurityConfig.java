package com.logickkun.vsoq.spring.authentication.server.config;

import com.logickkun.vsoq.spring.authentication.server.entity.Role;
import com.logickkun.vsoq.spring.authentication.server.repo.UserRepository;
import com.logickkun.vsoq.spring.authentication.server.tool.ModuleRoleValidator;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Locale;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthNSecurityConfig {

    private final ModuleRoleValidator roleValidator;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(CsrfConfigurer::disable)
                .httpBasic(HttpBasicConfigurer::disable)
                .formLogin(FormLoginConfigurer::disable)
                .authorizeHttpRequests(auth -> auth

                        .requestMatchers(
                                // 미인증 로그인 관련 주소
                                "/login",
                                "/auth/login",
                                // AuthZ만 호출(공유키로 보호)
                                "/internal/authn/verify",

                                // Static resources
                                "/index.html",
                                "/vite.svg",
                                "/assets/**",
                                "/favicon.ico"
                        ).permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll()
                )
                .build();
    }

    ///@Reference https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/dao-authentication-provider.html

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username  -> {

            // 여기선 이미 NormalizingAuthenticationToken에서 정규화 완료
            var user = userRepository.findByUsernameIgnoreCaseWithRoles(username)
                    .orElseThrow(() -> new UsernameNotFoundException("user"));

            var authorities = user.getRoles().stream()
                    .map(Role::getName)
                    .map(roleValidator::toAuthority)
                    .toList();

            // 4) UserDetails 조립
            return org.springframework.security.core.userdetails.User
                    .withUsername(user.getUsername())
                    .password(user.getPasswordHash())
                    .authorities(authorities) // "OBA_ADMIN", "POT_MANAGER", ...
                    .accountLocked(user.isLocked())
                    .disabled(!user.isEnabled())
                    .accountExpired(false)
                    .credentialsExpired(false)
                    .build();
        };
    }



    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService  userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        provider.setHideUserNotFoundExceptions(true);
        // (선택) 유출/취약 비밀번호 체크: provider.setCompromisedPasswordChecker(...); // 6.3+
        return new ProviderManager(provider);
    }
}
