package com.logickkun.vsoq.spring.authentication.server.svc;

import com.logickkun.vsoq.spring.authentication.server.entity.Role;
import com.logickkun.vsoq.spring.authentication.server.entity.User;
import com.logickkun.vsoq.spring.authentication.server.repo.UserRepository;
import com.logickkun.vsoq.spring.authentication.server.vo.AuthNVo;
import com.logickkun.vsoq.spring.authentication.server.vo.SessionVo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;


@Service("authNService")
@RequiredArgsConstructor
public class AuthNService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public SessionVo login(AuthNVo authNVo) {

        User user = userRepository.findByUsername(authNVo.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Invalid username"));

        if (!passwordEncoder.matches(authNVo.getPassword(), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        // 3) 인증 성공 → SessionVo 조립
        SessionVo session = new SessionVo();
        session.setUsername(user.getUsername());
        session.setRoles(
                user.getRoles()
                    .stream()
                    .map(Role::getName)
                    .collect(Collectors.toList())
        );
        return session;
    }
}
