package com.logickkun.vsoq.spring.authentication.server.svc;

import com.logickkun.vsoq.spring.authentication.server.config.NormalizingAuthenticationToken;
import com.logickkun.vsoq.spring.authentication.server.entity.Role;
import com.logickkun.vsoq.spring.authentication.server.entity.User;
import com.logickkun.vsoq.spring.authentication.server.repo.UserRepository;
import com.logickkun.vsoq.spring.authentication.server.vo.AuthNVo;
import com.logickkun.vsoq.spring.authentication.server.vo.SessionVo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;


@Service("authNService")
@RequiredArgsConstructor
public class AuthNService {

    private final AuthenticationManager authenticationManager;

    public SessionVo login(AuthNVo authNVo) {

        Authentication auth = authenticationManager.authenticate(
                NormalizingAuthenticationToken.unauthenticated(
                        authNVo.getUsername().trim(),
                        authNVo.getPassword()
                )
        );

        UserDetails principal = (UserDetails) auth.getPrincipal();

        SessionVo session = new SessionVo();
        session.setUsername(principal.getUsername());
        session.setRoles(
                principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        );

        return session;
    }
}
