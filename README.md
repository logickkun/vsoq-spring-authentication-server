<h3>🔐 OAuth 2.0 / OIDC 권장 흐름 요약</h3>
<p>
  <kbd>Client ➜ Authorization Server(AS/OP) ➜ 로그인/SSO</kbd><br>
  <kbd>AS가 사용자 인증 &amp; 인가 확인</kbd><br>
  <kbd>Authorization Code 발급 ➜ Token 교환(백엔드/BFF)</kbd><br>
  <kbd>Access Token(JWT)로 Resource Server 보호 API 호출</kbd>
</p>

<h4>왜 <code>POST /auth/login</code> 직접 로그인(ROPC 유사) 패턴이 비권장인가?</h4>
<ul>
  <li>현대 표준에서 제외/금지(Password Grant 폐기 추세)</li>
  <li>클라이언트가 자격증명(아이디/비번)을 직접 취급 → 보안 위험 증가</li>
  <li>표준 프로토콜 엔드포인트(/oauth2/authorize, /oauth2/token 등) 경유가 모범사례</li>
</ul>

<h4>프로토콜 엔드포인트(예)</h4>
<ul>
  <li><code>/oauth2/authorize</code> — 권한 부여(코드 발급)</li>
  <li><code>/oauth2/token</code> — 코드 ➜ 토큰 교환</li>
  <li><code>/oauth2/jwks</code> — 공개키(JWKS)</li>
  <li><code>/.well-known/openid-configuration</code> — OIDC 메타데이터</li>
</ul>

<h4>구성 태그</h4>
<p>
  <kbd>Spring Boot 3.5.3</kbd>
  <kbd>Spring Security 6.5.1</kbd>
  <kbd>Spring Authorization Server 1.5.1</kbd>
  <kbd>OAuth2 Resource Server 6.5.4</kbd>
  <kbd>Spring Data JPA</kbd>
  <kbd>Redis 7.4.5</kbd>
</p>

<hr>

<h4>📚 References</h4>
<ul>
  <li><a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 (OAuth 2.0)</a></li>
  <li><a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a></li>
  <li><a href="https://docs.spring.io/spring-authorization-server/reference/protocol-endpoints.html">Spring Authorization Server: Protocol Endpoints</a></li>
  <li><a href="https://oauth.net/2.1/">OAuth 2.1 (Draft Overview)</a></li>
  <li><a href="https://www.scottbrady.io/oauth/why-the-resource-owner-password-credentials-grant-type-is-not-authentication-nor-suitable-for-modern-applications">Why ROPC is not suitable</a></li>
</ul>
