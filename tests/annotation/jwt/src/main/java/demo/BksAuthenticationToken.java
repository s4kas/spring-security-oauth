package demo;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

public class BksAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;

	public BksAuthenticationToken(String token) {
		super(AuthorityUtils.NO_AUTHORITIES);
		setDetails(token);
	}
	
	public BksAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return "N/A";
	}

	@Override
	public Object getPrincipal() {
		return "N/A";
	}

}
