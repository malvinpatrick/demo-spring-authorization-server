package app.chameleon.authorization.server.oidc.authentication;

import java.time.Instant;
import java.util.Collections;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect 1.0
 * UserInfo Endpoint. Based on OidcUserInfoAuthenticationProvider, but using
 * BearerTokenAuthenticationToken for check supports
 * <p>
 * Based on OAuth2TokenIntrospectionAuthenticationProvider
 */
public class ChameleonOidcUserInfoAuthenticationBearerProvider implements AuthenticationProvider {

    private final Log logger = LogFactory.getLog(getClass());

    private final OAuth2AuthorizationService authorizationService;


    public ChameleonOidcUserInfoAuthenticationBearerProvider(OAuth2AuthorizationService authorizationService) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken userInfoAuthentication = (BearerTokenAuthenticationToken) authentication;

        if (userInfoAuthentication == null && authentication.isAuthenticated()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        String accessTokenValue = userInfoAuthentication.getToken();

        OAuth2Authorization authorization = this.authorizationService.findByToken(accessTokenValue,
                                                                                  OAuth2TokenType.ACCESS_TOKEN);

        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved authorization with access token");
        }

        OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();

        DefaultOAuth2AuthenticatedPrincipal authenticatedPrincipal = new DefaultOAuth2AuthenticatedPrincipal(
                authorization.getPrincipalName(), authorizedAccessToken.getClaims(), Collections.emptyList()
        );

        Instant iat = authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT);
        Instant exp = authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessTokenValue, iat,
                                                              exp);

        return new BearerTokenAuthentication(authenticatedPrincipal, accessToken, Collections.emptyList());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
