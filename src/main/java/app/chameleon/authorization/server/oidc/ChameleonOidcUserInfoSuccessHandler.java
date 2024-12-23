package app.chameleon.authorization.server.oidc;

import app.chameleon.authorization.server.oidc.converter.ChameleonOidcUserInfoHttpMessageConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ChameleonOidcUserInfoSuccessHandler implements AuthenticationSuccessHandler {

    private RegisteredClientRepository registeredClientRepository;
    private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
    };
    private final HttpMessageConverter<Map<String, Object>> userInfoHttpMessageConverter = new ChameleonOidcUserInfoHttpMessageConverter();

    public ChameleonOidcUserInfoSuccessHandler(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authentication) throws IOException, ServletException {
        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        OidcUserInfoAuthenticationToken userInfoAuthenticationToken = (OidcUserInfoAuthenticationToken) authentication;
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);

        Map<String, Object> claims = new HashMap<>(userInfoAuthenticationToken.getUserInfo().getClaims());
        claims.put("authorities", Arrays.asList(
                "a",
                "b"
        ));
        this.userInfoHttpMessageConverter.write(claims, null, httpResponse);

    }
}
