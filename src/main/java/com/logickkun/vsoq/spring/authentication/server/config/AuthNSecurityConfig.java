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


    /**
     * provider.setHideUserNotFoundExceptions(true) 하는 이유
     * 기본 동작
     * UserDetailsService.loadUserByUsername()에서 사용자를 찾지 못하면 UsernameNotFoundException이 발생합니다.
     * 반면, 사용자가 존재하지만 비밀번호가 틀리면 BadCredentialsException이 발생합니다.
     * 이 설정을 켜면
     * UsernameNotFoundException을 BadCredentialsException으로 감싸서 동일하게 처리합니다.
     * 따라서 로그인 실패 시 항상 “아이디 또는 비밀번호가 잘못되었습니다.”처럼 동일한 에러 메시지를 주게 됩니다.
     * 공격자가 username 존재 여부를 판별하기 어려워집니다.
     * ✅ 정리:
     * 목적 → 사용자 존재 여부를 숨겨서 계정 열거 공격 방어.
     * 실무에서는 거의 무조건 true로 둡니다.
     *
     *
     * (선택) provider.setCompromisedPasswordChecker(...) 하는 이유
     * Spring Security 6.3+에서 추가된 유출/취약 비밀번호 체크 기능입니다.
     *
     * 로그인 시도 시 입력한 비밀번호를 CompromisedPasswordChecker 구현체를 통해 검사합니다.
     *
     * 구현체 예:
     *
     * HaveIBeenPwnedPasswordChecker → HIBP API를 호출해 해당 비밀번호가 데이터 유출 목록에 있는지 확인.
     *
     * 사내 자체 취약 비밀번호 목록 DB 검사.
     *
     * 장점
     * 비밀번호가 유출된 기록이 있는 경우, 즉시 차단하거나 비밀번호 변경을 강제할 수 있습니다.
     *
     * 사용자들이 "123456", "password", "qwerty" 같은 너무 흔한 비밀번호를 쓰는 걸 방지할 수 있습니다.
     *
     * 보안 수준이 크게 향상됩니다.
     *
     * 단점/주의
     * 외부 API를 사용하면 네트워크 호출 지연이 로그인 성능에 영향.
     *
     * 개인정보 보호를 위해 평문 비밀번호를 직접 보내면 안 되고, k-Anonymity 방식 같은 안전한 조회 방식 사용 필요.
     *
     * ✅ 정리:
     * 목적 → 유출 이력 있는 비밀번호 사용 방지.
     * 선택 기능이지만 보안 민감 서비스(금융, 공공, 기업 내부망)에서는 적극 권장.
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService  userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        provider.setHideUserNotFoundExceptions(true);
        // (선택) 유출/취약 비밀번호 체크: provider.setCompromisedPasswordChecker(...); // 6.3+
        return new ProviderManager(provider);
    }
}
