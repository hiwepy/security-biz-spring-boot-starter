package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

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
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.AuthorizationPermissionEvaluator;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.biz.session.SessionAuthenticationFailureHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
import org.springframework.web.servlet.LocaleResolver;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *  基础对象初始化
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties({ SecurityBizProperties.class, SecuritySessionMgtProperties.class })
public class SecurityBizAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	protected LocaleContextFilter localeContextFilter(LocaleResolver localeResolver) {
		return new LocaleContextFilter(localeResolver);
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
	protected HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
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
	public RememberMeServices rememberMeServices() {
 		return new NullRememberMeServices();
 	}
	
	@Bean
	@ConditionalOnMissingBean
	public SessionRegistry sessionRegistry() {
 		return new SessionRegistryImpl();
 	}
	
	@Bean
	@ConditionalOnMissingBean
	public SessionInformationExpiredStrategy expiredSessionStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
 		return new SimpleRedirectSessionInformationExpiredStrategy(sessionMgtProperties.getFailureUrl());
 	}
	
	@Bean
	@ConditionalOnMissingBean
	public InvalidSessionStrategy invalidSessionStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				sessionMgtProperties.getFailureUrl());
		invalidSessionStrategy.setCreateNewSession(sessionMgtProperties.isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	/*@Configuration
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecuritySessionMgtProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 1)
   	static class DefaultWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    	
		private final SecuritySessionMgtProperties sessionMgtProperties;
		
	    private final InvalidSessionStrategy invalidSessionStrategy;
	    private final LogoutHandler logoutHandler;
	    private final LogoutSuccessHandler logoutSuccessHandler;
    	private final SessionRegistry sessionRegistry;
		private final SessionAuthenticationFailureHandler sessionAuthenticationFailureHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy expiredSessionStrategy;
		
   		public DefaultWebSecurityConfigurerAdapter (
   				
   				SecuritySessionMgtProperties sessionMgtProperties,
   				
   				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<SessionAuthenticationFailureHandler> sessionAuthenticationFailureHandlerProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<SessionInformationExpiredStrategy> expiredSessionStrategyProvider,
   				ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider
				
			) {
   			 
   			this.sessionMgtProperties = sessionMgtProperties;
			
   			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
   			this.logoutHandler = this.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
   			this.logoutSuccessHandler = this.logoutSuccessHandler();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			this.sessionAuthenticationFailureHandler = sessionAuthenticationFailureHandlerProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = this.sessionAuthenticationStrategy();
   			this.expiredSessionStrategy = expiredSessionStrategyProvider.getIfAvailable();
   			
   		}

   		
   		@Override
   		protected void configure(HttpSecurity http) throws Exception {
   			
   			// Session 管理器配置参数
	    	SecurityLogoutProperties logout = sessionMgtProperties.getLogout();
	    	
	    	// Session 管理器配置
	    	http.sessionManagement()
	    		.enableSessionUrlRewriting(sessionMgtProperties.isEnableSessionUrlRewriting())
	    		.invalidSessionStrategy(invalidSessionStrategy)
	    		.invalidSessionUrl(logout.getLogoutUrl())
	    		.maximumSessions(sessionMgtProperties.getMaximumSessions())
	    		.maxSessionsPreventsLogin(sessionMgtProperties.isMaxSessionsPreventsLogin())
	    		.expiredSessionStrategy(expiredSessionStrategy)
				.expiredUrl(logout.getLogoutUrl())
				.sessionRegistry(sessionRegistry)
				.and()
	    		.sessionAuthenticationErrorUrl(sessionMgtProperties.getFailureUrl())
	    		.sessionAuthenticationFailureHandler(sessionAuthenticationFailureHandler)
	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
	    		.sessionCreationPolicy(sessionMgtProperties.getCreationPolicy())
	    		// Session 注销配置
	    		.and()
	    		.logout()
	    		.logoutUrl(logout.getPathPatterns())
	    		.logoutSuccessUrl(logout.getLogoutSuccessUrl())
	    		.logoutSuccessHandler(logoutSuccessHandler)
	    		.addLogoutHandler(logoutHandler)
	    		.clearAuthentication(logout.isClearAuthentication())
	    		.invalidateHttpSession(logout.isInvalidateHttpSession());
	    	
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
   		
   		public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
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
   		
   	}*/

}
