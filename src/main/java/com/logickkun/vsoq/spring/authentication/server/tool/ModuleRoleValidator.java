package com.logickkun.vsoq.spring.authentication.server.tool;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import jakarta.annotation.PostConstruct;
import java.util.*;


@ConfigurationProperties(prefix = "app.role")
public class ModuleRoleValidator {

    /**
     * application.yml에서 주입되는 롤 접두사 리스트 (ROLE, OBA, DMC, ...)
     */
    private List<String> prefixes = new ArrayList<>();

    /**
     * 빠른 검사를 위해 Set으로 변환
     */
    private final Set<String> prefixSet = new HashSet<>();

    public ModuleRoleValidator(List<String> prefixes) {
        this.prefixes = prefixes;
    }

    @PostConstruct
    public void init() {
        // 대문자로 통일
        prefixes.replaceAll(p -> p.toUpperCase(Locale.ROOT));
        prefixSet.addAll(prefixes);
    }

    /**
     * 롤 문자열 검증
     * - 접두사는 설정된 값 중 하나여야 함
     * - 접두사 뒤에는 반드시 '_'가 있어야 함
     * - 전체는 대문자/숫자/언더스코어만 허용
     */
    public String validate(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("empty role");
        }
        String s = raw.trim().toUpperCase(Locale.ROOT);

        // 접두사 + 언더스코어 체크
        boolean validPrefix = prefixSet.stream().anyMatch(p -> s.startsWith(p + "_"));
        if (!validPrefix) {
            throw new IllegalArgumentException("invalid role prefix: " + raw);
        }

        // 형식 체크
        if (!s.matches("^[A-Z0-9_]+$")) {
            throw new IllegalArgumentException("invalid role format: " + raw);
        }

        return s;
    }

    /**
     * SimpleGrantedAuthority로 변환
     */
    public SimpleGrantedAuthority toAuthority(String raw) {
        return new SimpleGrantedAuthority(validate(raw));
    }
}
