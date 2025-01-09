package app.chameleon.authorization.server.config;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class DummyUserDetailService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		if(username.equals("user1")) {
			return User.withDefaultPasswordEncoder().username("user1").password("password").roles("USER").build();
		} else if(username.equals("user2")) {
			return User.withDefaultPasswordEncoder().username("user2").password("password").roles("USER").build();
		}
		
		return null;
	}

}
