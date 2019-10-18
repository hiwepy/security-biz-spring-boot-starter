package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class })
@ConditionalOnProperty(prefix = SecurityBizUpcProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityBizUpcProperties.class })
public class SecurityBizUpcFilterAutoConfiguration {

	@Autowired
	private SecurityBizUpcProperties bizUpcProperties;
	 
    @Bean
	@ConditionalOnMissingBean 
	public CaptchaResolver captchaResolver() {
		return new NullCaptchaResolver();
	}
    
	/*
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean 
	public LogoutFilter logoutFilter(List<LogoutHandler> logoutHandlers) {
		// 登录注销后的重定向地址：直接进入登录页面
		LogoutFilter logoutFilter = new LogoutFilter(bizUpcProperties.getLogout().getLogoutUrl(), logoutHandlers.toArray(new LogoutHandler[logoutHandlers.size()]));
		logoutFilter.setFilterProcessesUrl(bizUpcProperties.getLogout().getLogoutUrlPatterns());
		return logoutFilter;
	}
	
	@Configuration
    @ConditionalOnProperty(prefix = SecurityBizUpcProperties.PREFIX, value = "enabled", havingValue = "true")
   	@EnableConfigurationProperties({ SecurityBizUpcProperties.class, SecurityBizProperties.class })
	@Order(104)
   	static class UpcWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    	
        private final AuthenticationManager authenticationManager;
	    private final ObjectMapper objectMapper;
	    private final RememberMeServices rememberMeServices;
	    private final SessionRegistry sessionRegistry;
	    
	    private final SecurityBizProperties bizProperties;
    	private final SecurityBizUpcProperties bizUpcProperties;
	    private final PostRequestAuthenticationProvider authenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
	    private final CaptchaResolver captchaResolver;

		private final AuthenticatingFailureCounter authenticatingFailureCounter;
		private final CsrfTokenRepository csrfTokenRepository;
	    private final InvalidSessionStrategy invalidSessionStrategy;
    	private final RequestCache requestCache;
		private final SecurityContextLogoutHandler securityContextLogoutHandler;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
   		
   		public UpcWebSecurityConfigurerAdapter(
   				
   				SecurityBizProperties bizProperties,
   				SecurityBizUpcProperties bizUpcProperties,
   				
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<PostRequestAuthenticationProvider> authenticationProvider,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionInformationExpiredStrategy> sessionInformationExpiredStrategyProvider,
				
				@Qualifier("upcAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
				@Qualifier("upcSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider
				
			) {
   			
   			this.bizProperties = bizProperties;
   			this.bizUpcProperties = bizUpcProperties;
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.captchaResolver = captchaResolverProvider.getIfAvailable();
   			
   			this.authenticatingFailureCounter = authenticatingFailureCounter.getIfAvailable();
   			this.csrfTokenRepository = csrfTokenRepositoryProvider.getIfAvailable();
   			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
   			this.requestCache = requestCacheProvider.getIfAvailable();
   			this.securityContextLogoutHandler = securityContextLogoutHandlerProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategyProvider.getIfAvailable();
   			
   		}

   		public PostRequestAuthenticationProcessingFilter authenticationProcessingFilter() {
   			
   			// Form Login With Captcha
   			PostRequestAuthenticationProcessingFilter authenticationFilter = new PostRequestAuthenticationProcessingFilter(
   					objectMapper);
   			
   			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(bizUpcProperties.getCaptcha().getParamName()).to(authenticationFilter::setCaptchaParameter);
			map.from(bizUpcProperties.getCaptcha().isRequired()).to(authenticationFilter::setCaptchaRequired);
			map.from(captchaResolver).to(authenticationFilter::setCaptchaResolver);
			map.from(authenticatingFailureCounter).to(authenticationFilter::setFailureCounter);
			
			map.from(bizUpcProperties.getAuthc().getUsernameParameter()).to(authenticationFilter::setUsernameParameter);
			map.from(bizUpcProperties.getAuthc().getPasswordParameter()).to(authenticationFilter::setPasswordParameter);
			map.from(bizUpcProperties.getAuthc().isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(bizUpcProperties.getAuthc().getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);

			map.from(bizProperties.getRetry().getRetryTimesKeyAttribute()).to(authenticationFilter::setRetryTimesKeyAttribute);
			map.from(bizProperties.getRetry().getRetryTimesWhenAccessDenied()).to(authenticationFilter::setRetryTimesWhenAccessDenied);
			
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(bizUpcProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			
   			return authenticationFilter;
   		}
   		
   		@Override
   	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
   	        auth.authenticationProvider(authenticationProvider);
   	    }
   	    
   	    @Override
   	    protected void configure(HttpSecurity http) throws Exception {
   			
   			// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = bizUpcProperties.getLogout();
   	    	
   		    // Session 管理器配置
   	    	http.sessionManagement()
   	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
   	    		.invalidSessionStrategy(invalidSessionStrategy)
   	    		.invalidSessionUrl(bizUpcProperties.getLogout().getLogoutUrl())
   	    		.maximumSessions(sessionMgt.getMaximumSessions())
   	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
   	    		.expiredSessionStrategy(sessionInformationExpiredStrategy)
   				.expiredUrl(bizUpcProperties.getLogout().getLogoutUrl())
   				.sessionRegistry(sessionRegistry)
   				.and()
   	    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
   	    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
   	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
   	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
   	    		// Session 注销配置
   	    		.and()
   	    		.logout()
   	    		.addLogoutHandler(securityContextLogoutHandler)
   	    		.clearAuthentication(logout.isClearAuthentication())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	.and()
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 

   	       	// CSRF 配置
   	    	SecurityCsrfProperties csrf = bizUpcProperties.getCsrf();
   	    	if(csrf.isEnabled()) {
   	       		http.csrf()
   				   	.csrfTokenRepository(csrfTokenRepository)
   				   	.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
   					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
   	        } else {
   	        	http.csrf().disable();
   	        }
   	        
   	    }

   	}

}
