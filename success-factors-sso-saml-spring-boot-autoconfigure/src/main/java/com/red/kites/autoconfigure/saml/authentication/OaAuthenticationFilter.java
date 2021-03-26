package com.red.kites.autoconfigure.saml.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter
 */
public class OaAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private String companyParameter = "company";
    private String usernameParameter = "username";
    private String loginKeyParameter = "tklogin_key";
    private String expireParameter = "expire";
    private String callerhashParameter = "callerhash";
    private String tzParameter = "tz";


    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/oaLogin", "GET");

    public OaAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public OaAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String company = trim(this.obtainCompany(request));
        String username = trim(this.obtainUsername(request));
        String login_key = trim(this.obtainLoginKey(request));
        String expire = trim(this.obtainExpire(request));
        String callerhash = trim(this.obtainCallerhash(request));
        String tz = trim(this.obtainTz(request));
        OaAuthenticationToken authRequest = new OaAuthenticationToken(username, company, login_key, expire, callerhash, tz);
        this.setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    private String trim(String str) {
        str = str != null ? str : "";
        str = str.trim();
        return str;
    }

    protected void setDetails(HttpServletRequest request, OaAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    protected String obtainCompany(HttpServletRequest request) {
        return request.getParameter(this.companyParameter);
    }

    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(this.usernameParameter);
    }

    protected String obtainLoginKey(HttpServletRequest request) {
        return request.getParameter(this.loginKeyParameter);
    }


    protected String obtainExpire(HttpServletRequest request) {
        return request.getParameter(this.expireParameter);
    }


    protected String obtainCallerhash(HttpServletRequest request) {
        return request.getParameter(this.callerhashParameter);
    }

    protected String obtainTz(HttpServletRequest request) {
        return request.getParameter(this.tzParameter);
    }


    public String getCompanyParameter() {
        return companyParameter;
    }

    public void setCompanyParameter(String companyParameter) {
        this.companyParameter = companyParameter;
    }

    public String getUsernameParameter() {
        return usernameParameter;
    }

    public void setUsernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
    }

    public String getLoginKeyParameter() {
        return loginKeyParameter;
    }

    public void setLoginKeyParameter(String loginKeyParameter) {
        this.loginKeyParameter = loginKeyParameter;
    }

    public String getExpireParameter() {
        return expireParameter;
    }

    public void setExpireParameter(String expireParameter) {
        this.expireParameter = expireParameter;
    }

    public String getCallerhashParameter() {
        return callerhashParameter;
    }

    public void setCallerhashParameter(String callerhashParameter) {
        this.callerhashParameter = callerhashParameter;
    }

    public String getTzParameter() {
        return tzParameter;
    }

    public void setTzParameter(String tzParameter) {
        this.tzParameter = tzParameter;
    }
}
