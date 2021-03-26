package com.red.kites.autoconfigure.saml.authentication;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Provider
 */
public class OaAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(OaAuthenticationProvider.class);

    private OaUserDetailsService oaUserDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            String username = this.retrieveUser((OaAuthenticationToken) authentication);
            return this.createSuccessAuthentication(username, authentication);
        } catch (UsernameNotFoundException var6) {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    protected Authentication createSuccessAuthentication(Object principal, Authentication authentication) {
        OaAuthenticationToken result = new OaAuthenticationToken(principal, null);
        result.setDetails(authentication.getDetails());
        LOGGER.debug("Authenticated user");
        return result;
    }

    protected final String retrieveUser(OaAuthenticationToken authentication) throws AuthenticationException {

        try {
            String username = this.getOaUserDetailsService().loadOa(authentication);
            if (username == null) {
                throw new InternalAuthenticationServiceException("AuthCodeUserDetailsService returned null, which is an interface contract violation");
            }
            return username;
        } catch (OaParamErrorException oaParamErrorException) {
            throw oaParamErrorException;
        } catch (InternalAuthenticationServiceException internalAuthenticationServiceException) {
            throw internalAuthenticationServiceException;
        } catch (Exception exception) {
            throw new InternalAuthenticationServiceException(exception.getMessage(), exception);
        }
    }

    public OaUserDetailsService getOaUserDetailsService() {
        return oaUserDetailsService;
    }

    public void setOaUserDetailsService(OaUserDetailsService oaUserDetailsService) {
        this.oaUserDetailsService = oaUserDetailsService;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return OaAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
