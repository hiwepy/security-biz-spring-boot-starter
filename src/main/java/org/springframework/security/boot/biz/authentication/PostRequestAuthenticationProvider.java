package org.springframework.security.boot.biz.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class PostRequestAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public PostRequestAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService, final PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link UsernamePasswordAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException 认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        
		if (!StringUtils.hasLength(username)) {
			logger.debug("No principal found in request.");
			throw new BadCredentialsException("No principal found in request.");
		}

		if (!StringUtils.hasLength(password)) {
			logger.debug("No credentials found in request.");
			throw new BadCredentialsException("No credentials found in request.");
		}
        
        UserDetails ud = getUserDetailsService().loadUserDetails(authentication);
        if (!passwordEncoder.matches(password, ud.getPassword())) {
            throw new BadCredentialsException("Authentication Failed. Username or Password not valid.");
        }
        
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        UsernamePasswordAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	authenticationToken = new UsernamePasswordAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new UsernamePasswordAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
	
}
