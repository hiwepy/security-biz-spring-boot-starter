package org.springframework.security.boot;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.boot.biz.IgnoreLogoutHandler;
import org.springframework.security.boot.biz.SessionAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.*;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.*;
import org.springframework.security.boot.biz.property.SecurityFailureRetryProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.*;
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
import org.springframework.web.servlet.LocaleResolver;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.stream.Collectors;

/**
 *  基础对象初始化
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	protected LocaleContextFilter localeContextFilter(ObjectProvider<LocaleResolver> localeResolverProvider) {
		return new LocaleContextFilter(localeResolverProvider.getIfAvailable());
	}

	@Bean
	@ConditionalOnMissingBean
	protected HttpFirewall httpFirewall() {
		return new StrictHttpFirewall();
	}

	@Bean
	@ConditionalOnMissingBean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}

	@Bean
	@ConditionalOnMissingBean
	public GrantedAuthoritiesMapper authoritiesMapper() {
		return new NullAuthoritiesMapper();
	}

	@Bean
	@ConditionalOnMissingBean
	public PermissionEvaluator permissionEvaluator() {
		return new AuthorizationPermissionEvaluator();
	}

    @Bean
	@ConditionalOnMissingBean
	public CaptchaResolver captchaResolver() {
		return new NullCaptchaResolver();
	}

    @Bean
   	@ConditionalOnMissingBean
   	public LogoutHandler ignoreLogoutHandler() {
   		return new IgnoreLogoutHandler();
   	}

	@Bean
	@ConditionalOnMissingBean
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	@Bean
	@ConditionalOnMissingBean
	public RedirectStrategy redirectStrategy(SecurityBizProperties bizProperties) {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(bizProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}

	@Bean
	@ConditionalOnMissingBean
	public RequestCache requestCache(SecurityBizProperties bizProperties) {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setCreateSessionAllowed(bizProperties.getSession().isAllowSessionCreation());
		requestCache.setSessionAttrName(bizProperties.getSession().getSessionAttrName());
		return requestCache;
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionAuthenticationStrategy(SecurityBizProperties bizProperties) {
		// Session 管理器配置参数
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(bizProperties.getSession().getFixationPolicy())) {
			return new ChangeSessionIdAuthenticationStrategy();
		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(bizProperties.getSession().getFixationPolicy())) {
			return new SessionFixationProtectionStrategy();
		} else if (SessionFixationPolicy.NEW_SESSION.equals(bizProperties.getSession().getFixationPolicy())) {
			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
			return sessionFixationProtectionStrategy;
		} else {
			return new NullAuthenticatedSessionStrategy();
		}
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionInformationExpiredStrategy sessionInformationExpiredStrategy(SecurityBizProperties bizProperties) {
		return new SimpleRedirectSessionInformationExpiredStrategy(bizProperties.getSession().getFailureUrl(), redirectStrategy(bizProperties));
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}


	@Bean
	@ConditionalOnMissingBean
	public CsrfTokenRepository csrfTokenRepository(SecurityBizProperties bizProperties) {
		// Session 管理器配置参数
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(bizProperties.getSession().getFixationPolicy())) {
			return new CookieCsrfTokenRepository();
		}
		return new HttpSessionCsrfTokenRepository();
	}

	@Bean
	@ConditionalOnMissingBean
	public InvalidSessionStrategy invalidSessionStrategy(SecurityBizProperties bizProperties) {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				bizProperties.getSession().getFailureUrl());
		invalidSessionStrategy.setCreateNewSession(bizProperties.getSession().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticatingFailureCounter authenticatingFailureCounter(SecurityBizProperties bizProperties) {
		AuthenticatingFailureRequestCounter failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(bizProperties.getRetry().getRetryTimesKeyParameter());
		return failureCounter;
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
	public IngoringWebSecurityCustomizer ingoringWebSecurityCustomizer(SecurityBizProperties bizProperties) {
		return new IngoringWebSecurityCustomizer(bizProperties);
	}

	@Configuration
	@EnableConfigurationProperties({ SecurityBizProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 0)
	static class BizWebSecurityConfigurerAdapter extends SecurityFilterChainConfigurer {

		private final SecurityBizProperties bizProperties;

		private final CsrfTokenRepository csrfTokenRepository;
		private final InvalidSessionStrategy invalidSessionStrategy;
		private final LogoutHandler logoutHandler;
		private final LogoutSuccessHandler logoutSuccessHandler;
		private final RequestCache requestCache;
		private final RememberMeServices rememberMeServices;
		private final SessionRegistry sessionRegistry;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionAuthenticationFailureHandler sessionAuthenticationFailureHandler;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

		public BizWebSecurityConfigurerAdapter (

				SecurityBizProperties bizProperties,

				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
				ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				ObjectProvider<LogoutHandler> logoutHandlerProvider,
				ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
				ObjectProvider<RedirectStrategy> redirectStrategyProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionAuthenticationFailureHandler> sessionAuthenticationFailureHandlerProvider,
				ObjectProvider<SessionInformationExpiredStrategy> sessionInformationExpiredStrategyProvider

		) {

			super(bizProperties, redirectStrategyProvider.getIfAvailable(), requestCacheProvider.getIfAvailable());

			this.bizProperties = bizProperties;

			this.csrfTokenRepository = csrfTokenRepositoryProvider.getIfAvailable();
			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
			this.logoutSuccessHandler = logoutSuccessHandlerProvider.getIfAvailable();
			this.requestCache = requestCacheProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
			this.sessionAuthenticationFailureHandler = sessionAuthenticationFailureHandlerProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
			this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategyProvider.getIfAvailable();

		}

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		public SecurityFilterChain iniSecurityFilterChain(HttpSecurity http) throws Exception {
			// 跨站请求配置
			http.csrf(this.csrfCustomizer(bizProperties.getCsrf(), csrfTokenRepository))
				// 跨域配置
				.cors(this.corsCustomizer(bizProperties.getCors()))
				// 请求头配置
				.headers(this.headersCustomizer(bizProperties.getHeaders()))
				// RememberMe 配置
				.rememberMe(this.rememberMeCustomizer(rememberMeServices))
				// Session 管理器配置参数
				.sessionManagement(this.sessionManagementCustomizer(
						invalidSessionStrategy, sessionRegistry, sessionInformationExpiredStrategy,
						sessionAuthenticationFailureHandler, sessionAuthenticationStrategy))
				// Session 注销配置
				.logout(this.logoutCustomizer(bizProperties.getLogout(), logoutHandler, logoutSuccessHandler))
				// 匿名访问配置
				.anonymous(this.anonymousCustomizer())
				// 请求鉴权配置
				.authorizeRequests(this.authorizeRequestsCustomizer());

			return http.build();
		}

	}

}
