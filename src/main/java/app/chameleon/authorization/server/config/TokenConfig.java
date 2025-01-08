package app.chameleon.authorization.server.config;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration(proxyBeanMethods = false)
public class TokenConfig {


	/**
	 * https://docs.spring.io/spring-authorization-server/reference/core-model-components.html#oauth2-token-customizer
	 */
	
    @Bean
    OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer(){
        return context -> {
            System.out.print("");
            if ((AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
                    || AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType()))
                    && OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();

                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                authorities.add("dsca.faktur");

                context.getClaims().claim("authorities", authorities);
            }
        };
    }
}
