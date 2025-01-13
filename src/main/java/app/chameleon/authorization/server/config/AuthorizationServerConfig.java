package app.chameleon.authorization.server.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;

import app.chameleon.authorization.server.jose.Jwks;
import app.chameleon.authorization.server.oidc.authentication.CustomOidcUserInfoAuthenticationBearerProvider;
import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    private static final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa(); JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            AuthorizationServerSettings authorizationServerSettings,
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        // @formatter:off
        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                .registeredClientRepository(registeredClientRepository)
                .authorizationServerSettings(authorizationServerSettings)	
                .oidc(oidc -> oidc
        			.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                        .authenticationProviders(providers -> {
                            // I need to add the custom provider here to support the UserInfo endpoint with opaque bearer tokens
                            // providers.add(new CustomOidcUserInfoAuthenticationBearerProvider(getAuthorizationService(http)));
                        })
					)
        		)
            )
            .authorizeHttpRequests(authorize -> authorize
        		.anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth -> oauth
                .authenticationManagerResolver(authenticationManagerResolver)
            )
            .exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            );

        // @formatter:on
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .authorizeHttpRequests((authorize) -> authorize
        		.requestMatchers("/assets/**", "/login").permitAll()
        		.anyRequest().authenticated()
            )
            .cors(Customizer.withDefaults())
            // Form login handles the redirect to the login page from the
            // authorization server filter chain
            .formLogin(Customizer.withDefaults())
            .headers(headers -> headers
                .frameOptions((frameOptions) -> frameOptions.disable())
            )
        ;

        return http.build();
        // @formatter:on
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("test-client-1")
                .clientSecret("{noop}secret1")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://angular-client-1.devbz.local:8081/login/oauth2/code/test-client-1")
                .redirectUri("http://angular-client-1.devbz.local:8081/authorized")
                .postLogoutRedirectUri("http://angular-client-1.devbz.local:8081/logged-out").scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE).scope("message.read").scope("message.write").scope("user.read")
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                .clientSettings(
                        ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);
        repository.save(client);

        return repository;
    }

    @Bean
    public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JdbcOAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        // Will be used by the ConsentController
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public EmbeddedDatabase embeddedDatabase() {
        // @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver(JwtDecoder jwtDecoder,
            HttpSecurity httpSecurity) {

        // Setup JWT AuthenticationManager
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        jwtAuthenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter());
        AuthenticationManager jwtAuthenticationManager = new ProviderManager(jwtAuthenticationProvider);

        // Setup opaque token AuthenticationManager
        AuthenticationProvider opaqueTokenAuthenticationProvider = new CustomOidcUserInfoAuthenticationBearerProvider(
                getAuthorizationService(httpSecurity));
        AuthenticationManager opaqueTokenAuthenticationManager = new ProviderManager(opaqueTokenAuthenticationProvider);

        return (request) -> isJwt(request) ? jwtAuthenticationManager : opaqueTokenAuthenticationManager;
    }

    private static boolean isJwt(HttpServletRequest request) {
        String accessToken = bearerTokenResolver.resolve(request); if (!StringUtils.hasText(accessToken)) {
            return false;
        } try {
            Base64URL[] parts = JOSEObject.split(accessToken); if (parts.length == 3) {
                // 3 parts expected for Signed JWT
                return true;
            }
        } catch (Exception ignored) {
        }

        return false;
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter());
        return jwtAuthenticationConverter;
    }

    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter() {
        // Use 'scope' or 'scp' claim (the default) to extract authorities
        JwtGrantedAuthoritiesConverter defaultAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        // Use 'authorities' claim to extract authorities
        JwtGrantedAuthoritiesConverter customAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        customAuthoritiesConverter.setAuthorityPrefix("");
        customAuthoritiesConverter.setAuthoritiesClaimName("authorities");

        return (jwt) -> {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.addAll(defaultAuthoritiesConverter.convert(jwt));
            authorities.addAll(customAuthoritiesConverter.convert(jwt)); return authorities;
        };
    }

    static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
        OAuth2AuthorizationService authorizationService = httpSecurity.getSharedObject(
                OAuth2AuthorizationService.class); if (authorizationService == null) {
            authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);
            if (authorizationService == null) {
                authorizationService = new InMemoryOAuth2AuthorizationService();
            } httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        } return authorizationService;
    }

    static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
                httpSecurity.getSharedObject(ApplicationContext.class), type); if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                                                      "Expected single matching bean of type '" + type.getName() + "' but found " + beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(
                                                              beansMap.keySet()));
        } return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }

}
