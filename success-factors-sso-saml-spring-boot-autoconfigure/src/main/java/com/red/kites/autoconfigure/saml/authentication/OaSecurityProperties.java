package com.red.kites.autoconfigure.saml.authentication;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.oa.login")
public class OaSecurityProperties {

    /**
     * 公司
     */
    private String company;
    /**
     * secretKey
     */
    private String secretKey;
    /**
     * tk_login_key
     */
    private String tkoginKey;
    /**
     * tz
     */
    private String tz;
    /**
     * oaCode 解密
     */
    private String oaTokenDecryptKey;

    private String spEntityId;

    private String serverBaseUrl;

    public String getCompany() {
        return company;
    }

    public void setCompany(String company) {
        this.company = company;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTkoginKey() {
        return tkoginKey;
    }

    public void setTkoginKey(String tkoginKey) {
        this.tkoginKey = tkoginKey;
    }

    public String getTz() {
        return tz;
    }

    public void setTz(String tz) {
        this.tz = tz;
    }

    public String getOaTokenDecryptKey() {
        return oaTokenDecryptKey;
    }

    public void setOaTokenDecryptKey(String oaTokenDecryptKey) {
        this.oaTokenDecryptKey = oaTokenDecryptKey;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public void setSpEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public String getServerBaseUrl() {
        return serverBaseUrl;
    }

    public void setServerBaseUrl(String serverBaseUrl) {
        this.serverBaseUrl = serverBaseUrl;
    }
}
