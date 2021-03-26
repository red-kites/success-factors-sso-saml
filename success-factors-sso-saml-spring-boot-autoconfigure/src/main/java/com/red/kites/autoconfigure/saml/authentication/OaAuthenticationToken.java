package com.red.kites.autoconfigure.saml.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.util.Collection;

public class OaAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;

    /**
     * 公司
     */
    private String company;
    /**
     * 用户名base64 -> principal
     */
    // private String username;

    /**
     * loginKey
     */
    private String tklogin_key;

    /**
     * 过期时间
     */
    private String expire;

    /**
     * 签名
     */
    private String callerhash;

    /**
     * 业务别名
     */
    private String tz;


    public OaAuthenticationToken(Object principal,
                                 String company,
                                 String tklogin_key,
                                 String expire,
                                 String callerhash,
                                 String tz) {
        super(null);
        this.principal = principal;
        this.company = company;
        this.tklogin_key = tklogin_key;
        this.expire = expire;
        this.callerhash = callerhash;
        this.tz = tz;

        setAuthenticated(false);
    }


    public OaAuthenticationToken(Object principal,
                                 Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }

    public String getCompany() {
        return company;
    }

    public String getTklogin_key() {
        return tklogin_key;
    }

    public String getExpire() {
        return expire;
    }

    public String getCallerhash() {
        return callerhash;
    }

    public String getTz() {
        return tz;
    }
}
