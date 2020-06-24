package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Security Form Filter Auto Configuration
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class })
@ConditionalOnProperty(prefix = SecurityFormProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityFormProperties.class })
public class SecurityFormFilterAutoConfiguration {


	@Bean("formLogoutHandler")
	public SecurityContextLogoutHandler formLogoutHandler(SecurityFormProperties authcProperties) {
		
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		
		logoutHandler.setClearAuthentication(authcProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(authcProperties.getLogout().isInvalidateHttpSession());
		
		return logoutHandler;
	}
	
	@Bean("formAuthenticationProvider")
	public PostRequestAuthenticationProvider formAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
	}
	
	@Configuration
	@EnableConfigurationProperties({ SecurityBizProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 1)
   	static class FormWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {
    	
	    private final SecurityFormProperties authcProperties;
		
	    private final AuthenticatingFailureCounter authenticatingFailureCounter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final CaptchaResolver captchaResolver;
	    private final InvalidSessionStrategy invalidSessionStrategy;
	    private final LogoutHandler logoutHandler;
	    private final ObjectMapper objectMapper;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
    	private final SessionRegistry sessionRegistry;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
		
   		public FormWebSecurityConfigurerAdapter (
   				
   				SecurityBizProperties bizProperties,
   				SecurityFormProperties authcProperties,
   				
   				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider
				
			) {
   			
			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
			
			this.authcProperties = authcProperties;
   			
   			this.authenticatingFailureCounter = super.authenticatingFailureCounter();
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.captchaResolver = captchaResolverProvider.getIfAvailable();
   			this.invalidSessionStrategy = super.invalidSessionStrategy();
   			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.requestCache = super.requestCache();
   			this.rememberMeServices = super.rememberMeServices();
   			this.sessionRegistry = super.sessionRegistry();
   			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
   			this.sessionInformationExpiredStrategy = super.sessionInformationExpiredStrategy();
   			
   		}

   		public PostRequestAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   			
   			// Form Login With Captcha
   			PostRequestAuthenticationProcessingFilter authenticationFilter = new PostRequestAuthenticationProcessingFilter(
   					objectMapper);
   			
   			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getCaptcha().getParamName()).to(authenticationFilter::setCaptchaParameter);
			map.from(authcProperties.getCaptcha().isRequired()).to(authenticationFilter::setCaptchaRequired);
			map.from(captchaResolver).to(authenticationFilter::setCaptchaResolver);
			map.from(authenticatingFailureCounter).to(authenticationFilter::setFailureCounter);
			
			map.from(authcProperties.getUsernameParameter()).to(authenticationFilter::setUsernameParameter);
			map.from(authcProperties.getPasswordParameter()).to(authenticationFilter::setPasswordParameter);
			map.from(authcProperties.isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);

			map.from(authcProperties.getRetry().getRetryTimesKeyAttribute()).to(authenticationFilter::setRetryTimesKeyAttribute);
			map.from(authcProperties.getRetry().getRetryTimesWhenAccessDenied()).to(authenticationFilter::setRetryTimesWhenAccessDenied);
			
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			
   			return authenticationFilter;
   		}
   	    
   	    @Override
   	    public void configure(HttpSecurity http) throws Exception {
   			
   			// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = authcProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = authcProperties.getLogout();
   	    	
   		    // Session 管理器配置
   	    	http.sessionManagement()
   	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
   	    		.invalidSessionStrategy(invalidSessionStrategy)
   	    		.invalidSessionUrl(logout.getLogoutUrl())
   	    		.maximumSessions(sessionMgt.getMaximumSessions())
   	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
   	    		.expiredSessionStrategy(sessionInformationExpiredStrategy)
   				.expiredUrl(logout.getLogoutUrl())
   				.sessionRegistry(sessionRegistry)
   				.and()
   	    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
   	    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
   	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
   	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
   	    		// Session 注销配置
   	    		.and()
   	    		.logout()
   	    		.logoutUrl(logout.getPathPatterns())
   	    		.logoutSuccessUrl(logout.getLogoutSuccessUrl())
   	    		.addLogoutHandler(logoutHandler)
   	    		.clearAuthentication(logout.isClearAuthentication())
   	    		.invalidateHttpSession(logout.isInvalidateHttpSession())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	// 异常处理
   	        	.and()
   	        	.exceptionHandling()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.httpBasic()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.antMatcher(authcProperties.getPathPattern())
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 

   	    	super.configure(http, authcProperties.getCors());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
   	    	
   	    }
   	    
   	    @Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	super.configure(web);
   	    }

   	}

}
