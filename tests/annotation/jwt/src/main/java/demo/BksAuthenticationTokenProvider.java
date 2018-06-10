package demo;

import java.util.Arrays;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class BksAuthenticationTokenProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		System.out.println("\"Always authenticate to true\" dummy provider");
		return new BksAuthenticationToken(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return BksAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
