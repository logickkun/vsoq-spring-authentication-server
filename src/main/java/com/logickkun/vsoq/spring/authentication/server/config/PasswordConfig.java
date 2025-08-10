package com.logickkun.vsoq.spring.authentication.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {


//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

    /**
     * 멀티 알고리즘 지원: 기본은 {bcrypt}이지만 {id} 접두사로 PBKDF2, Argon2 등 지원
     * DB 저장 포맷:
     * 예: {bcrypt}$2a$10$...
     * 호환성: 접두사에 따라 자동으로 해당 알고리즘 인코더 사용
     * 장점: 해시 업그레이드, 알고리즘 변경이 유연
     * 단점: DB에 {id} 접두사가 붙음 (기존 bcrypt 해시와 호환하려면 설정 필요)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}

