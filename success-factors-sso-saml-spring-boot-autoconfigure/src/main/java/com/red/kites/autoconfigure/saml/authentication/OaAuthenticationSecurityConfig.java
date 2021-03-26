package com.red.kites.autoconfigure.saml.authentication;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class OaAuthenticationSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final OaAuthenticationProvider oaAuthenticationProvider;

    public OaAuthenticationSecurityConfig(AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler, OaAuthenticationProvider oaAuthenticationProvider) {
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.oaAuthenticationProvider = oaAuthenticationProvider;
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        OaAuthenticationFilter oaAuthenticationFilter = new OaAuthenticationFilter();
        oaAuthenticationFilter.setAuthenticationManager(builder.getSharedObject(AuthenticationManager.class));
        oaAuthenticationFilter.setAuthenticationSuccessHandler(successHandler);
        oaAuthenticationFilter.setAuthenticationFailureHandler(failureHandler);
        builder.authenticationProvider(oaAuthenticationProvider).addFilterAfter(oaAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
