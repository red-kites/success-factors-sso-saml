package com.red.kites.autoconfigure.saml.authentication;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public interface OaUserDetailsService {

    String loadOa(OaAuthenticationToken oa) throws UnsupportedEncodingException, NoSuchAlgorithmException;
}
