package com.red.kites.autoconfigure.saml.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;

@Configuration
@EnableConfigurationProperties(OaSecurityProperties.class)
public class OaSecurityConfigAutoConfiguration {

    @Autowired
    private OaSecurityProperties oaSecurityProperties;

    @Bean
    @ConditionalOnMissingBean
    public FilterRegistrationBean registerFilter() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new SkipUrlFilter(oaSecurityProperties.getSpEntityId(), oaSecurityProperties.getServerBaseUrl()));
        registration.addUrlPatterns("/");
        return registration;
    }


    @Bean
    @ConditionalOnMissingBean
    public OaUserDetailsService oaUserDetailsService() {
        return param -> {
            if (param.getCallerhash() == null) {
                throw new OaParamErrorException("Param Error");
            }
            if (param.getPrincipal() == null) {
                throw new OaParamErrorException("Param Error");
            }
            if (!oaSecurityProperties.getCompany().equalsIgnoreCase(param.getCompany())) {
                throw new OaParamErrorException("Param Error");
            }
            if (!oaSecurityProperties.getTz().equalsIgnoreCase(param.getTz())) {
                throw new OaParamErrorException("Param Error");
            }
            if (!oaSecurityProperties.getTkoginKey().equalsIgnoreCase(param.getTklogin_key())) {
                throw new OaParamErrorException("Param Error");
            }
            String callerHash = SSOUtils.getEncrypt(param.getPrincipal() + URLDecoder.decode(param.getExpire()) + oaSecurityProperties.getSecretKey());
            if (!param.getCallerhash().equalsIgnoreCase(callerHash)) {
                throw new OaParamErrorException("Param Error");
            }
            byte[] bytes = param.getPrincipal().toString().getBytes(StandardCharsets.UTF_8);
            return new String(Base64.getDecoder().decode(bytes));
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationSuccessHandler successHandler() {
        return new SavedRequestAwareAuthenticationSuccessHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationFailureHandler failureHandler() {
        return new SimpleUrlAuthenticationFailureHandler();
    }

    @Bean
    public OaAuthenticationProvider oaAuthenticationProvider() {
        OaAuthenticationProvider authCodeAuthenticationProvider = new OaAuthenticationProvider();
        authCodeAuthenticationProvider.setOaUserDetailsService(oaUserDetailsService());
        return authCodeAuthenticationProvider;
    }

    @Bean
    @ConditionalOnMissingBean
    public UserDetailsService userDetailsService() {
        return username -> new UserDetails() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.NO_AUTHORITIES;
            }

            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public String getUsername() {
                return username;
            }

            @Override
            public boolean isAccountNonExpired() {
                return true;
            }

            @Override
            public boolean isAccountNonLocked() {
                return true;
            }

            @Override
            public boolean isCredentialsNonExpired() {
                return true;
            }

            @Override
            public boolean isEnabled() {
                return true;
            }
        };
    }

    @Bean
    public OaAuthenticationSecurityConfig authCodeAuthenticationSecurityConfig() {
        return new OaAuthenticationSecurityConfig(successHandler(), failureHandler(), oaAuthenticationProvider());
    }
}
