package com.logickkun.vsoq.spring.authentication.server.config;

import com.logickkun.vsoq.spring.authentication.server.tool.ModuleRoleValidator;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(ModuleRoleValidator.class)
public class RoleConfig {
}