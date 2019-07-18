package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

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

	@Bean("upcRedirectStrategy")
	public RedirectStrategy upcRedirectStrategy() {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(bizUpcProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}

	@Bean("upcRequestCache")
	public RequestCache upcRequestCache() {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setCreateSessionAllowed(bizUpcProperties.getSessionMgt().isAllowSessionCreation());
		requestCache.setSessionAttrName(bizUpcProperties.getSessionMgt().getSessionAttrName());
		// requestCache.setRequestMatcher(requestMatcher);
		// requestCache.setSessionAttrName(sessionAttrName);
		return requestCache;
	}

	@Bean("upcInvalidSessionStrategy")
	public InvalidSessionStrategy upcInvalidSessionStrategy() {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				bizUpcProperties.getAuthc().getRedirectUrl());
		invalidSessionStrategy.setCreateNewSession(bizUpcProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean("upcExpiredSessionStrategy")
	public SessionInformationExpiredStrategy upcExpiredSessionStrategy(RedirectStrategy redirectStrategy) {
		return new SimpleRedirectSessionInformationExpiredStrategy(bizUpcProperties.getAuthc().getRedirectUrl(), redirectStrategy);
	}
	
	@Bean("upcCsrfTokenRepository")
	public CsrfTokenRepository upcCsrfTokenRepository() {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = bizUpcProperties.getSessionMgt();
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgt.getFixationPolicy())) {
			return new CookieCsrfTokenRepository();
		}
		return new HttpSessionCsrfTokenRepository();
	}

	@Bean("upcSessionAuthenticationStrategy")
	public SessionAuthenticationStrategy upcSessionAuthenticationStrategy() {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = bizUpcProperties.getSessionMgt();
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

	@Bean("upcSecurityContextLogoutHandler")
	public SecurityContextLogoutHandler upcSecurityContextLogoutHandler() {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setClearAuthentication(bizUpcProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(bizUpcProperties.getLogout().isInvalidateHttpSession());

		return logoutHandler;
	}
	
	@Bean("upcAuthenticatingFailureCounter")
	public AuthenticatingFailureCounter upcAuthenticatingFailureCounter() {
		AuthenticatingFailureRequestCounter failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(bizUpcProperties.getAuthc().getRetryTimesKeyParameter());
		return failureCounter;
	}
	
	@Bean("upcAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler upcAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers, 
			@Qualifier("upcRedirectStrategy") RedirectStrategy redirectStrategy, 
			@Qualifier("upcRequestCache") RequestCache requestCache) {
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
	
	@Bean("upcAuthenticationFailureHandler")
	public PostRequestAuthenticationFailureHandler upcAuthenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationFailureHandler> failureHandlers, 
			@Qualifier("upcRedirectStrategy") RedirectStrategy redirectStrategy) {
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);
		failureHandler.setAllowSessionCreation(bizUpcProperties.getAuthc().isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(bizUpcProperties.getAuthc().getFailureUrl());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setStateless(bizProperties.isStateless());
		failureHandler.setUseForward(bizUpcProperties.getAuthc().isUseForward());
		return failureHandler;
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
