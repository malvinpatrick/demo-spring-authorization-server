package app.chameleon.authorization.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class CorsConfiguration implements WebMvcConfigurer {
	
	@Override
	public void addCorsMappings(CorsRegistry registry) {

		registry.addMapping("/connect/**")
			.allowedOrigins("http://angular-client-1.devbz.local")
			.allowedMethods("GET", "POST", "PUT", "DELETE")
			.allowCredentials(true)
			.maxAge(3600);
	}

}
