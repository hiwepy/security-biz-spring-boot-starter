package org.springframework.security.boot;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.biz.userdetails.BaseAuthenticationUserDetailsService;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(name = { "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration" })
@ConditionalOnProperty(prefix = SecurityBizProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizAutoConfiguration {

	@Autowired
	private SecurityBizProperties bizProperties;

	@Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}

	@Bean
	@ConditionalOnMissingBean
	public RedirectStrategy redirectStrategy() {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(bizProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}

	@Bean
	@ConditionalOnMissingBean
	public RequestCache requestCache() {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setCreateSessionAllowed(bizProperties.getSessionMgt().isAllowSessionCreation());
		// requestCache.setPortResolver(portResolver);
		// requestCache.setRequestMatcher(requestMatcher);
		// requestCache.setSessionAttrName(sessionAttrName);
		return requestCache;
	}

	@Bean
	@ConditionalOnMissingBean
	public InvalidSessionStrategy invalidSessionStrategy() {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				bizProperties.getRedirectUrl());
		invalidSessionStrategy.setCreateNewSession(bizProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionInformationExpiredStrategy expiredSessionStrategy(RedirectStrategy redirectStrategy) {
		return new SimpleRedirectSessionInformationExpiredStrategy(bizProperties.getRedirectUrl(), redirectStrategy);
	}
	
	 
	@Bean
	@ConditionalOnMissingBean
	public CsrfTokenRepository csrfTokenRepository() {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgt.getFixationPolicy())) {
			return new CookieCsrfTokenRepository();
		}
		return new HttpSessionCsrfTokenRepository();
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionStrategy() {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgt.getFixationPolicy())) {
			return new ChangeSessionIdAuthenticationStrategy();
		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(sessionMgt.getFixationPolicy())) {
			return new SessionFixationProtectionStrategy();
		} else if (SessionFixationPolicy.NEW_SESSION.equals(sessionMgt.getFixationPolicy())) {
			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
			return sessionFixationProtectionStrategy;
		} else {
			return new NullAuthenticatedSessionStrategy();
		}
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	@Bean
	@ConditionalOnMissingBean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	protected HttpFirewall httpFirewall() {
		return new StrictHttpFirewall();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationSuccessHandler authenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			RedirectStrategy redirectStrategy, RequestCache requestCache) {
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, bizProperties.getSuccessUrl());
		successHandler.setRedirectStrategy(redirectStrategy);
		successHandler.setRequestCache(requestCache);
		successHandler.setTargetUrlParameter(bizProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(bizProperties.getAuthc().isUseReferer());
		return successHandler;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationFailureHandler authenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			RedirectStrategy redirectStrategy) {
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, bizProperties.getFailureUrl());
		failureHandler.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setUseForward(bizProperties.getAuthc().isUseForward());
		return failureHandler;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint() {

		PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint(
				bizProperties.getAuthc().getLoginUrl());
		entryPoint.setForceHttps(bizProperties.getAuthc().isForceHttps());
		entryPoint.setUseForward(bizProperties.getAuthc().isUseForward());

		return entryPoint;
	}

	@Bean
	@ConditionalOnMissingBean
	public SecurityContextLogoutHandler securityContextLogoutHandler() {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setClearAuthentication(bizProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(bizProperties.getLogout().isInvalidateHttpSession());

		return logoutHandler;
	}

	@Bean
	public PostRequestAuthenticationProvider postRequestAuthenticationProvider(
			BaseAuthenticationUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
		return new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
	}

	@Bean
	public IdentityCodeAuthenticationProvider mobileCodeAuthenticationProvider(
			BaseAuthenticationUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
		return new IdentityCodeAuthenticationProvider(userDetailsService, passwordEncoder);
	}

}
