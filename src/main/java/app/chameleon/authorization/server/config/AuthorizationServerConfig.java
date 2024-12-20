package app.chameleon.authorization.server.config;

import java.util.Arrays;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            AuthorizationServerSettings authorizationServerSettings
    ) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        // @formatter:off
        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, (authorizationServer) ->
                authorizationServer
                    .registeredClientRepository(registeredClientRepository)
                    .authorizationServerSettings(authorizationServerSettings)
                    .oidc(Customizer.withDefaults())
            )
            .headers(headers -> headers
                .frameOptions((frameOptions) -> frameOptions.disable())
            )
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> authorize
//            		.requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.OPTIONS, "/**")).permitAll()
            		.anyRequest().authenticated()
            )
            .oauth2ResourceServer((resourceServer) ->
                resourceServer
                    .jwt(Customizer.withDefaults())
            )
            .authenticationProvider(new OpaqueTokenAuthenticationProvider(
        		new SpringOpaqueTokenIntrospector("http://localhost:9000/oauth2/introspect", "dsca-bff1", "secret1"))
    		)
            .exceptionHandling((exceptions) ->
               exceptions
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
//        		.requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.OPTIONS, "/**")).permitAll()
//        		.requestMatchers("/assets/**", "/login").permitAll()
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
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

        RegisteredClient clientDscaBff = repository.findByClientId("dsca-bff1");
        if (clientDscaBff == null) {
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("dsca-bff1")
                    .clientSecret("{noop}secret1")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://angular-client-1.devbz.local:8081/login/oauth2/code/dsca-bff1")
                    .redirectUri("http://angular-client-1.devbz.local:8081/authorized")
                    .postLogoutRedirectUri("http://angular-client-1.devbz.local:8081/logged-out")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("message.read").scope("message.write").scope("user.read")
                    .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build()).build();

            repository.save(client);
        }

        RegisteredClient clientDscaBff2 = repository.findByClientId("dsca-bff2");
        if (clientDscaBff2 == null) {
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("dsca-bff2")
                    .clientSecret("{noop}secret2")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://angular-client-2.devbz.local:8082/login/oauth2/code/dsca-bff2")
                    .redirectUri("http://angular-client-2.devbz.local:8082/authorized")
                    .postLogoutRedirectUri("http://angular-client-2.devbz.local:8082/logged-out")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE).scope("message.read").scope("message.write").scope("user.read")
                    .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build()).build();

            repository.save(client);
        }


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
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer(){
        return context -> {
    		System.out.print("");
//            if ((AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
//                    || AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType()))
//                    && OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                Authentication principal = context.getPrincipal();
//                
//                Set<String> authorities = principal.getAuthorities().stream()
//                        .map(GrantedAuthority::getAuthority)
//                        .collect(Collectors.toSet());
//                authorities.add("SCOPE_message.read");
//                context.getClaims().claim("authorities", authorities);
//            } else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
//                Authentication principal = context.getPrincipal();
//                Set<String> authorities = principal.getAuthorities().stream()
//                        .map(GrantedAuthority::getAuthority)
//                        .collect(Collectors.toSet());
//                context.getClaims().claim("authorities", authorities);
//            } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
//                Authentication principal = context.getPrincipal();
//                if("dsca-bff2".equals(principal.getName())) {
//                    List<String> authorities = new ArrayList<>();
//                    authorities.add("SCOPE_message.read");
//                    context.getClaims().claim("authorities", authorities);
//                }
//            }
        };
    }
    
    @Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.addAllowedHeader("X-XSRF-TOKEN");
		config.addAllowedHeader(HttpHeaders.CONTENT_TYPE);
		config.setAllowedMethods(Arrays.asList("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"));
		config.setAllowedOrigins(Arrays.asList(
                "null",
				"http://angular-client-1.devbz.local:4200",
    			"http://localhost",
    			"http://127.0.0.1"
			));
		config.setAllowCredentials(true);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}
    
//    @Bean
//    UrlBasedCorsConfigurationSource corsConfigurationSource() {
//    	CorsConfiguration configuration = new CorsConfiguration();
//    	configuration.setAllowedOrigins(Arrays.asList(
//    			"http://angular-client-1.devbz.local",
//    			"http://localhost", 
//    			"http://127.0.0.1"
//			));
//    	configuration.setAllowedMethods(Arrays.asList("GET","POST", "OPTIONS"));
//    	
//    	UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//    	source.registerCorsConfiguration("/**", configuration);
//    	return source;
//    }

}
