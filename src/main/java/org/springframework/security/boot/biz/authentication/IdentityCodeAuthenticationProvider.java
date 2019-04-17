package org.springframework.security.boot.biz.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.userdetails.LoginAuthenticationUserDetailsService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

public class IdentityCodeAuthenticationProvider implements AuthenticationProvider {
	
    private final PasswordEncoder passwordEncoder;
    private final LoginAuthenticationUserDetailsService userDetailsService;
    
    public IdentityCodeAuthenticationProvider(final LoginAuthenticationUserDetailsService userDetailsService, final PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
        String mobile = (String) authentication.getPrincipal();
        String code = (String) authentication.getCredentials();
        
        UserDetails user = null;
		try {
			user = userDetailsService.loadUserDetails(authentication);
		} catch (UsernameNotFoundException e) {
			throw new UsernameNotFoundException("User not registered: " + mobile, e);
		}
        if (!passwordEncoder.matches(code, user.getPassword())) {
            throw new BadCredentialsException("Authentication Failed. Code not valid.");
        }
        
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
        authenticationToken.setDetails(authentication.getDetails());
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
