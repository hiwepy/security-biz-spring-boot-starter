package org.springframework.security.boot;

import java.util.List;

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
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
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
@Order(105)
public class SecurityBizFilterAutoConfiguration extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	
	@Autowired
	private SecurityBizUpcProperties bizUpcProperties;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RememberMeServices rememberMeServices;
	@Autowired
    private SessionRegistry sessionRegistry;
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	@Qualifier("upcAuthenticatingFailureCounter")
	private AuthenticatingFailureCounter upcAuthenticatingFailureCounter;
	@Autowired
	@Qualifier("upcSessionAuthenticationStrategy")
	private SessionAuthenticationStrategy upcSessionAuthenticationStrategy;
    @Autowired
    @Qualifier("upcCsrfTokenRepository")
	private CsrfTokenRepository upcCsrfTokenRepository;
    @Autowired
    @Qualifier("upcExpiredSessionStrategy")
    private SessionInformationExpiredStrategy upcExpiredSessionStrategy;
    @Autowired
    @Qualifier("upcRequestCache")
    private RequestCache upcRequestCache;
    @Autowired
    @Qualifier("upcInvalidSessionStrategy")
    private InvalidSessionStrategy upcInvalidSessionStrategy;
    @Autowired
    @Qualifier("upcSecurityContextLogoutHandler") 
    private SecurityContextLogoutHandler upcSecurityContextLogoutHandler;
    @Autowired(required = false)
    private CaptchaResolver captchaResolver;
    @Autowired
	private PostRequestAuthenticationSuccessHandler postRequestAuthenticationSuccessHandler;
	@Autowired
	private PostRequestAuthenticationFailureHandler postRequestAuthenticationFailureHandler;
    @Autowired
    private PostRequestAuthenticationProvider postRequestAuthenticationProvider;
    @Autowired
    private PostRequestAuthenticationEntryPoint postRequestAuthenticationEntryPoint;
    
	@Bean
	public PostRequestAuthenticationProcessingFilter postRequestAuthenticationProcessingFilter() {
		
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
		authcFilter.setFailureCounter(upcAuthenticatingFailureCounter);

		authcFilter.setAllowSessionCreation(bizUpcProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(postRequestAuthenticationFailureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(postRequestAuthenticationSuccessHandler);
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
		authcFilter.setSessionAuthenticationStrategy(upcSessionAuthenticationStrategy);
		return authcFilter;
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
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(postRequestAuthenticationProvider)
        	.userDetailsService(userDetailsService);
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
		
		// Session 管理器配置参数
    	SecuritySessionMgtProperties sessionMgt = bizUpcProperties.getSessionMgt();
    	// Session 注销配置参数
    	SecurityLogoutProperties logout = bizUpcProperties.getLogout();
    	
	    // Session 管理器配置
    	http.sessionManagement()
    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
    		.invalidSessionStrategy(upcInvalidSessionStrategy)
    		.invalidSessionUrl(bizUpcProperties.getLogout().getLogoutUrl())
    		.maximumSessions(sessionMgt.getMaximumSessions())
    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
    		.expiredSessionStrategy(upcExpiredSessionStrategy)
			.expiredUrl(bizUpcProperties.getLogout().getLogoutUrl())
			.sessionRegistry(sessionRegistry)
			.and()
    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
    		.sessionAuthenticationFailureHandler(postRequestAuthenticationFailureHandler)
    		.sessionAuthenticationStrategy(upcSessionAuthenticationStrategy)
    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
    		// Session 注销配置
    		.and()
    		.logout()
    		.addLogoutHandler(upcSecurityContextLogoutHandler)
    		.clearAuthentication(logout.isClearAuthentication())
        	// Request 缓存配置
        	.and()
    		.requestCache()
        	.requestCache(upcRequestCache)
        	.and()
        	.addFilterBefore(postRequestAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 
        
        http.exceptionHandling().authenticationEntryPoint(postRequestAuthenticationEntryPoint);
 

       	// CSRF 配置
    	SecurityCsrfProperties csrf = bizUpcProperties.getCsrf();
    	if(csrf.isEnabled()) {
       		http.csrf()
			   	.csrfTokenRepository(upcCsrfTokenRepository)
			   	.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        } else {
        	http.csrf().disable();
        }
        
    }
     
	
	/**
	 * 	这里需要提供UserDetailsService的原因是RememberMeServices需要用到
	 * 	@return UserDetailsService
	@Override
	protected UserDetailsService userDetailsService() {
		return userDetailsService;
	} */
    
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
