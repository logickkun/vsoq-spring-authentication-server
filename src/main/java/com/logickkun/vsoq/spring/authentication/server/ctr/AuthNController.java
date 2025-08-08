package com.logickkun.vsoq.spring.authentication.server.ctr;


import com.logickkun.vsoq.spring.authentication.server.svc.AuthNService;
import com.logickkun.vsoq.spring.authentication.server.vo.ApiResponse;
import com.logickkun.vsoq.spring.authentication.server.vo.AuthNVo;
import com.logickkun.vsoq.spring.authentication.server.vo.SessionVo;
import jakarta.annotation.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthNController {

    @Resource(name="authNService")
    private AuthNService authNService;

    @RequestMapping("/login")
    public ResponseEntity<ApiResponse<SessionVo>> login(@RequestBody AuthNVo authNVo) {
        SessionVo session = authNService.login(authNVo);
        ApiResponse<SessionVo> resp = new ApiResponse<>(true, "로그인 성공", session);
        return ResponseEntity.ok(resp);
    }

}
