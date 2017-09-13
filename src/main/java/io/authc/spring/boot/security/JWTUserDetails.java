package io.authc.spring.boot.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * 
 * @className	： JWTUserDetails
 * @description	： JWT保存的用户信息
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月13日 下午7:22:30
 * @version 	V1.0
 */
@SuppressWarnings("serial")
public class JWTUserDetails extends User {

	private final Long userId;
	private final String secret;

	public JWTUserDetails(long userId, String username, String password,
			Collection<? extends GrantedAuthority> authorities, String secret) {
		this(userId, username, password, true, true, true, true, authorities, secret);
	}

	public JWTUserDetails(long userId, String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities, String secret) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		if (username != null && !"".equals(username) && password != null) {
			this.userId = userId;
			this.secret = secret;
		} else {
			throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
		}
	}

	public Long getUserId() {
		return userId;
	}

	public String getSecret() {
		return secret;
	}
	
}