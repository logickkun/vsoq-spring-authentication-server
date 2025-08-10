package com.logickkun.vsoq.spring.authentication.server.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Locale;

/**
 * 이렇게 하면 username 대소문자/공백 처리 로직이 전역 통일돼서 나중에 다른 로그인 엔드포인트를 추가해도 중복 코드가 없음
 */
public class NormalizingAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public NormalizingAuthenticationToken(Object principal, Object credentials) {
        super(normalize(principal), credentials);
    }

    public static NormalizingAuthenticationToken unauthenticated(String username, String password) {
        return new NormalizingAuthenticationToken(username, password);
    }

    // 1) 사용자명 정규화: 앞뒤 공백 제거 + 로캘 독립적 대문자화
    /// 왜 Locale.ROOT인가?
    /// toLowerCase(Locale.ROOT) / toUpperCase(Locale.ROOT)는 로캘 독립적 변환
    ///
    /// 시스템/사용자 기본 로캘을 쓰면 언어별 특수 규칙(대표적으로 터키어 i/İ)이 적용돼서,
    /// "ADMIN".toLowerCase(tr_TR) → "admın" 같이 예상치 못한 문자열이 나올 수 있음 하지만 DB에 LowerCase 설정을 해서 상관은 없지만 일관 적인 환경설정 유지
    ///
    /// 아이디/이메일/키 같은 규칙이 고정돼야 하는 식별자는 항상 동일한 결과가 나와야 하므로 Locale.ROOT를 사용해 언어 영향 배제하는 게 베스트.
    private static String normalize(Object principal) {
        if (principal == null) return "";
        return principal.toString().trim().toUpperCase(Locale.ROOT);
    }
}
