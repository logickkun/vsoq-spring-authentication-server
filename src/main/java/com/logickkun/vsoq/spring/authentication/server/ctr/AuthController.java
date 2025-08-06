package com.logickkun.vsoq.spring.authentication.server.ctr;


import com.logickkun.vsoq.spring.authentication.server.svc.AuthService;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Resource(name="authService")
    private AuthService authService;


}
