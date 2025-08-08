package com.logickkun.vsoq.spring.authentication.server.vo;

import lombok.*;

import java.time.Instant;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SessionVo {

    private String id;

    private String username;

    private List<String> roles;          // 권한 리스트

    private String accessToken;          // JWT 액세스 토큰
    private String refreshToken;         // 리프레시 토큰

    private Instant accessTokenExpiry;   // 액세스 토큰 만료 시각
    private Instant refreshTokenExpiry;  // 리프레시 토큰 만료 시각

}
