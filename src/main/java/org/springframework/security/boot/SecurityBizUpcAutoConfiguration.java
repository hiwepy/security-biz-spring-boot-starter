package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@ConditionalOnProperty(prefix = SecurityBizUpcProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityBizUpcProperties.class })
public class SecurityBizUpcAutoConfiguration {
	
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private SecurityBizUpcProperties bizUpcProperties;
	
	@Bean("upcSecurityContextLogoutHandler")
	public SecurityContextLogoutHandler upcSecurityContextLogoutHandler() {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setClearAuthentication(bizUpcProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(bizUpcProperties.getLogout().isInvalidateHttpSession());

		return logoutHandler;
	}
	
	@Bean("upcAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler upcAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers, 
			RedirectStrategy redirectStrategy, 
			RequestCache requestCache) {
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		successHandler.setDefaultTargetUrl(bizUpcProperties.getAuthc().getSuccessUrl());
		successHandler.setRedirectStrategy(redirectStrategy);
		successHandler.setRequestCache(requestCache);
		successHandler.setStateless(bizProperties.isStateless());
		successHandler.setTargetUrlParameter(bizUpcProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(bizUpcProperties.getAuthc().isUseReferer());
		return successHandler;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedAuthenticationFailureHandler defaultMatchedAuthenticationFailureHandler() {
		return new DefaultMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedAuthenticationEntryPoint defaultMatchedAuthenticationEntryPoint() {
		return new DefaultMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public PostRequestAuthenticationProvider postRequestAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
	}


}
