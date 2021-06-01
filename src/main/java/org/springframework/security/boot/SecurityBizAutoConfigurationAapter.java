package org.springframework.security.boot;

import java.util.List;

import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

public class SecurityBizAutoConfigurationAapter {

	protected AccessDeniedHandler accessDeniedHandler() {
		AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
		return accessDeniedHandler;
	}
	
	protected AuthenticatingFailureCounter authenticatingFailureCounter(SecurityAuthcProperties authcProperties) {
		AuthenticatingFailureRequestCounter failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(authcProperties.getRetry().getRetryTimesKeyParameter());
		return failureCounter;
	}

	protected PostRequestAuthenticationEntryPoint authenticationEntryPoint(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<MatchedAuthenticationEntryPoint> entryPoints) {
		PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint(
				authcProperties.getPathPattern(), entryPoints);
		entryPoint.setForceHttps(authcProperties.getEntryPoint().isForceHttps());
		entryPoint.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		entryPoint.setUseForward(authcProperties.getEntryPoint().isUseForward());
		return entryPoint;
	}
	
	protected PostRequestAuthenticationFailureHandler authenticationFailureHandler(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {

		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);

		failureHandler.setAllowSessionCreation(sessionMgtProperties.isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
		failureHandler.setRedirectStrategy(this.redirectStrategy(authcProperties));
		failureHandler.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		failureHandler.setUseForward(authcProperties.isUseForward());

		return failureHandler;

	}
	
	protected ForwardAuthenticationFailureHandler authenticationFailureForwardHandler(String forwardUrl) {
		return new ForwardAuthenticationFailureHandler(forwardUrl);
	}
	
	protected SimpleUrlAuthenticationFailureHandler authenticationFailureSimpleUrlHandler(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties ) {

		SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

		failureHandler.setAllowSessionCreation(sessionMgtProperties.isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
		failureHandler.setRedirectStrategy(this.redirectStrategy(authcProperties));
		failureHandler.setUseForward(authcProperties.isUseForward());

		return failureHandler;
	}

	public PostRequestAuthenticationProvider authenticationProvider(UserDetailsServiceAdapter userDetailsService,
			PasswordEncoder passwordEncoder) {
		return new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
	}
	
	protected PostRequestAuthenticationSuccessHandler authenticationSuccessHandler(
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {

		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		successHandler.setAlwaysUseDefaultTargetUrl(authcProperties.isAlwaysUseDefaultTargetUrl());
		successHandler.setDefaultTargetUrl(authcProperties.getSuccessUrl());
		successHandler.setRedirectStrategy(this.redirectStrategy(authcProperties));
		successHandler.setRequestCache(this.requestCache(authcProperties, sessionMgtProperties));
		successHandler.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		successHandler.setTargetUrlParameter(authcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(authcProperties.isUseReferer());

		return successHandler;
	}
	
	protected RequestCache requestCache(SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties) {
 		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
 		requestCache.setCreateSessionAllowed(sessionMgtProperties.isAllowSessionCreation());
 		requestCache.setSessionAttrName(sessionMgtProperties.getSessionAttrName());
 		return requestCache;
 	}
	
	protected RedirectStrategy redirectStrategy(SecurityAuthcProperties authcProperties) {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(authcProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}
	
	protected LogoutHandler logoutHandler(List<LogoutHandler> logoutHandlers) {
		return new CompositeLogoutHandler(logoutHandlers);
	}
	
	protected LogoutSuccessHandler logoutSuccessHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}

	protected LogoutSuccessHandler logoutSuccessForwardHandler(String targetUrl) {
		return new ForwardLogoutSuccessHandler(targetUrl);
	}
	
	protected LogoutSuccessHandler logoutSuccessSimpleUrlHandler() {
		return new SimpleUrlLogoutSuccessHandler();
	}
	
	public SessionAuthenticationStrategy sessionAuthenticationStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
 		// Session 管理器配置参数
 		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new ChangeSessionIdAuthenticationStrategy();
 		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new SessionFixationProtectionStrategy();
 		} else if (SessionFixationPolicy.NEW_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
 			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
 			return sessionFixationProtectionStrategy;
 		} else {
 			return new NullAuthenticatedSessionStrategy();
 		}
 	}

}
