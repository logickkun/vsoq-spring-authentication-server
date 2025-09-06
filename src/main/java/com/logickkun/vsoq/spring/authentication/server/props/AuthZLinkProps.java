package com.logickkun.vsoq.spring.authentication.server.props;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * application.yml 의 "authz" 프리픽스를 바인딩.
 * authz.internal-key -> internalKey 로 매핑됨.
 */
@ConfigurationProperties(prefix = "authz")
public record AuthZLinkProps(
        String internalKey
) {}
