package com.logickkun.vsoq.spring.authentication.server.ctr;

import com.logickkun.vsoq.spring.authentication.server.config.NormalizingAuthenticationToken;
import com.logickkun.vsoq.spring.authentication.server.props.AuthZLinkProps;
import com.logickkun.vsoq.spring.authentication.server.vo.AuthNVo;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 부* AuthZ → AuthN 내 위임 검증 엔드포인트.
 * - 외부 노출 금지 가정(게이트웨이 라우팅/보안그룹 등으로 보호)
 *  * - "X-AuthZ-Key" 헤더로 공유키 검증
 * - 성공 시 roles와 함께 {success:true} 반환, 실패 시 {success:false}
 * - 절대 비밀번호 등 민감정보를 로그로 남기지 말 것
 */
@Slf4j
@RestController
@RequestMapping("/internal/authn")
@RequiredArgsConstructor
public class InternalAuthNController {

    private final AuthenticationManager authenticationManager;
    private final AuthZLinkProps authzProps;  // <<< 주입받기



    @PostMapping(
            value = "/verify",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<VerifyResponse> verify(
            @RequestHeader(name = "X-AuthZ-Key", required = false) String key,
            @Valid @RequestBody AuthNVo body
    ) {

        log.info("InternalAuthNController.verify() 로그인 네번째 진입");
        // 1) 공유키 체크 (constant-time 비교)
        if (key == null || !constantTimeEquals(authzProps.internalKey(), key)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new VerifyResponse(false, List.of()));
        }

        try {
            // 2) 인증 시도 (네가 사용 중인 NormalizingAuthenticationToken로 통일)
            Authentication result = authenticationManager.authenticate(
                    NormalizingAuthenticationToken.unauthenticated(
                            body.getUsername(), body.getPassword())
            );

            // 3) 권한 수집
            List<String> roles = new ArrayList<>();
            for (GrantedAuthority ga : result.getAuthorities()) {
                roles.add(ga.getAuthority());
            }

            // 4) 성공 응답
            return ResponseEntity.ok(new VerifyResponse(true, roles));

        } catch (AuthenticationException ex) {
            // 자격 증명 오류/잠김 등은 모두 false로 응답
            return ResponseEntity.ok(new VerifyResponse(false, List.of()));
        }
    }


    // 타이밍 공격 완화용 비교: 길이가 달라도 전체 루프 수행
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        int diff = x.length ^ y.length;
        int len = Math.max(x.length, y.length);
        for (int i = 0; i < len; i++) {
            byte bx = i < x.length ? x[i] : 0;
            byte by = i < y.length ? y[i] : 0;
            diff |= (bx ^ by);
        }
        return diff == 0;
    }

    // AuthZ가 기대하는 응답 형태
    public record VerifyResponse(boolean success, List<String> roles) {}
}
