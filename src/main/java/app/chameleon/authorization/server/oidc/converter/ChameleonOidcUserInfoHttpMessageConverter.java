package app.chameleon.authorization.server.oidc.converter;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import java.io.IOException;
import java.util.Map;

public final class ChameleonOidcUserInfoHttpMessageConverter extends AbstractHttpMessageConverter<Map<String, Object>> {

    private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
    };

    private final GenericHttpMessageConverter<Object> jsonMessageConverter = ChameleonHttpMessageConverter.getJsonMessageConverter();

    private Converter<OidcUserInfo, Map<String, Object>> userInfoParametersConverter = OidcUserInfo::getClaims;

    public ChameleonOidcUserInfoHttpMessageConverter() {
        super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return Map.class.isAssignableFrom(clazz);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected Map<String, Object> readInternal(Class<? extends Map<String, Object>> clazz,
            HttpInputMessage inputMessage) throws HttpMessageNotReadableException {

        try {
            Map<String, Object> userInfoParameters = (Map<String, Object>) this.jsonMessageConverter.read(
                    STRING_OBJECT_MAP.getType(), null, inputMessage); return userInfoParameters;
        } catch (Exception ex) {
            throw new HttpMessageNotReadableException(
                    "An error occurred reading the UserInfo response: " + ex.getMessage(), ex, inputMessage);
        }
    }

    @Override
    protected void writeInternal(Map<String, Object> userInfoResponseParameters,
            HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
        try {
            this.jsonMessageConverter.write(userInfoResponseParameters, STRING_OBJECT_MAP.getType(),
                                            MediaType.APPLICATION_JSON, outputMessage);
        } catch (Exception ex) {
            throw new HttpMessageNotWritableException(
                    "An error occurred writing the UserInfo response: " + ex.getMessage(), ex);
        }
    }
}
