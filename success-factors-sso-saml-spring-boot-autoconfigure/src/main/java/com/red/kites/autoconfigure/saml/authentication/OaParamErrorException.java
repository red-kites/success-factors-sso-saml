package com.red.kites.autoconfigure.saml.authentication;

import org.springframework.security.core.AuthenticationException;

public class OaParamErrorException extends AuthenticationException {
    public OaParamErrorException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public OaParamErrorException(String msg) {
        super(msg);
    }
}
