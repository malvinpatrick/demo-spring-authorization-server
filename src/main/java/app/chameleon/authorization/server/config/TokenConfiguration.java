package app.chameleon.authorization.server.config;

import app.chameleon.authorization.server.jose.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

@Configuration(proxyBeanMethods = false)
public class TokenConfiguration {

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa(); JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

//    @Bean
//    public OpaqueTokenIntrospector opaqueTokenIntrospector() {
//        return new SpringOpaqueTokenIntrospector(
//                "http://localhost:9000/oauth2/introspect",
//                "dsca-bff2",
//                "secret2"
//        );
//    }
//
//    @Bean
//    public DefaultBearerTokenResolver bearerTokenResolver() {
//        DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
//        bearerTokenResolver.setBearerTokenHeaderName(HttpHeaders.AUTHORIZATION);
//        return bearerTokenResolver;
//    }
//
//    /**
//     * https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html
//     */
//    @Bean
//    public AuthenticationManagerResolver<HttpServletRequest> tokenAuthenticationManagerResolver(
//            BearerTokenResolver bearerTokenResolver,
//            JwtDecoder jwtDecoder,
//            OpaqueTokenIntrospector opaqueTokenIntrospector) {Ø
//
//        AuthenticationManager jwt = new ProviderManager(new JwtAuthenticationProvider(jwtDecoder));
//        AuthenticationManager opaqueToken = new ProviderManager(
//                new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector));
//
//        return (request) -> authorizationIsJwt(bearerTokenResolver.resolve(request)) ? jwt : opaqueToken;
//    }
//
//    private boolean authorizationIsJwt(String bearerToken) {
//        String[] jwtSplitted = bearerToken.split("\\.");
//        return jwtSplitted.length == 3;
//    }


//    @Bean
//    public OAuth2TokenGenerator<?> tokenGenerator(
//            OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer) {
//        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
//        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
//
//        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
//
//        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//
//        return new DelegatingOAuth2TokenGenerator(
//                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
//    }
//
//    @Bean
//    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
//        return context -> {
//            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
//            // Customize claims
//
//        };
//    }
//    public OAuth2TokenGenerator<?> tokenGenerator(
//            OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer) {
//        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
//        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
//
//        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
//
//        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//
//        return new DelegatingOAuth2TokenGenerator(
//                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
//    }
//
//    @Bean
//    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
//        return context -> {
//            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
//            // Customize claims
//
//        };
//    }
}
