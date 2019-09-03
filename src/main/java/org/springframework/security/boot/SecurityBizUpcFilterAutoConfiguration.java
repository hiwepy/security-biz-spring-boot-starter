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
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
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
   	static class UpcWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {
    	
    	private ApplicationEventPublisher eventPublisher;
    	
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
		private final SessionInformationExpiredStrategy expiredSessionStrategy;
   		
   		public UpcWebSecurityConfigurerAdapter(
   				
   				SecurityBizProperties bizProperties,
   				SecurityBizUpcProperties bizUpcProperties,
   				
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<SessionRegistry> sessionRegistryProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
   				ObjectProvider<PostRequestAuthenticationProvider> authenticationProvider,
   				@Qualifier("upcAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				@Qualifier("upcAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				
   				@Qualifier("upcAuthenticatingFailureCounter") ObjectProvider<AuthenticatingFailureCounter> authenticatingFailureCounter,
   				@Qualifier("upcCsrfTokenRepository") ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				@Qualifier("upcInvalidSessionStrategy") ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
				@Qualifier("upcRequestCache") ObjectProvider<RequestCache> requestCacheProvider,
				@Qualifier("upcSecurityContextLogoutHandler")  ObjectProvider<SecurityContextLogoutHandler> securityContextLogoutHandlerProvider,
				@Qualifier("upcSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				@Qualifier("upcExpiredSessionStrategy") ObjectProvider<SessionInformationExpiredStrategy> expiredSessionStrategyProvider
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
   			this.expiredSessionStrategy = expiredSessionStrategyProvider.getIfAvailable();
   			
   		}

   		@Bean
   		public PostRequestAuthenticationProcessingFilter authenticationProcessingFilter() {
   			
   			// Form Login With Captcha
   			PostRequestAuthenticationProcessingFilter authcFilter = new PostRequestAuthenticationProcessingFilter(
   					objectMapper);

   			authcFilter.setCaptchaParameter(bizUpcProperties.getCaptcha().getParamName());
   			// 是否验证码必填
   			authcFilter.setCaptchaRequired(bizUpcProperties.getCaptcha().isRequired());
   			// 登陆失败重试次数，超出限制需要输入验证码
   			authcFilter.setRetryTimesWhenAccessDenied(bizUpcProperties.getCaptcha().getRetryTimesWhenAccessDenied());
   			// 验证码解析器
   			authcFilter.setCaptchaResolver(captchaResolver);
   			// 认证失败计数器
   			authcFilter.setFailureCounter(authenticatingFailureCounter);

   			authcFilter.setAllowSessionCreation(bizUpcProperties.getAuthc().isAllowSessionCreation());
   			authcFilter.setApplicationEventPublisher(eventPublisher);
   			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
   			authcFilter.setAuthenticationManager(authenticationManager);
   			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
   			authcFilter.setContinueChainBeforeSuccessfulAuthentication(bizUpcProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
   			if (StringUtils.hasText(bizUpcProperties.getAuthc().getLoginUrlPatterns())) {
   				authcFilter.setFilterProcessesUrl(bizUpcProperties.getAuthc().getLoginUrlPatterns());
   			}
   			//authcFilter.setMessageSource(messageSource);
   			authcFilter.setUsernameParameter(bizUpcProperties.getAuthc().getUsernameParameter());
   			authcFilter.setPasswordParameter(bizUpcProperties.getAuthc().getPasswordParameter());
   			authcFilter.setPostOnly(bizUpcProperties.getAuthc().isPostOnly());
   			authcFilter.setRememberMeServices(rememberMeServices);
   			authcFilter.setRetryTimesKeyAttribute(bizUpcProperties.getAuthc().getRetryTimesKeyAttribute());
   			authcFilter.setRetryTimesWhenAccessDenied(bizUpcProperties.getAuthc().getRetryTimesWhenAccessDenied());
   			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
   			return authcFilter;
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
   	    		.expiredSessionStrategy(expiredSessionStrategy)
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
   	    
   		@Override
   		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
   			this.eventPublisher = applicationEventPublisher;
   		}

   	}

}
