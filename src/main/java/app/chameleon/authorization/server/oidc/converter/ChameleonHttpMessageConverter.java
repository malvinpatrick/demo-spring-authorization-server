package app.chameleon.authorization.server.oidc.converter;

import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.ClassUtils;

public final class ChameleonHttpMessageConverter {
    private static final boolean jackson2Present;

    private static final boolean gsonPresent;

    private static final boolean jsonbPresent;

    static {
        ClassLoader classLoader = ChameleonHttpMessageConverter.class.getClassLoader();
        jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper",
                                               classLoader) && ClassUtils.isPresent(
                "com.fasterxml.jackson.core.JsonGenerator", classLoader);
        gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);
        jsonbPresent = ClassUtils.isPresent("jakarta.json.bind.Jsonb", classLoader);
    }

    private ChameleonHttpMessageConverter() {
    }

    static GenericHttpMessageConverter<Object> getJsonMessageConverter() {
        if (jackson2Present) {
            return new MappingJackson2HttpMessageConverter();
        } if (gsonPresent) {
            return new GsonHttpMessageConverter();
        } if (jsonbPresent) {
            return new JsonbHttpMessageConverter();
        } return null;
    }
}
