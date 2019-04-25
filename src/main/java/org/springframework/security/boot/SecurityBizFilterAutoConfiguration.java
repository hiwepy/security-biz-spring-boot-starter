package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.boot.biz.authentication.IdentityCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
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
	private AuthenticatingFailureCounter authenticatingFailureCounter;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private AuthenticationSuccessHandler successHandler;
	@Autowired
	private AuthenticationFailureHandler failureHandler;
	@Autowired
	private RememberMeServices rememberMeServices;
	@Autowired
	private SessionAuthenticationStrategy sessionStrategy;
	//@Autowired
	//private MessageSource messageSource;
    @Autowired(required = false) 
    private CaptchaResolver captchaResolver;
    @Autowired
	private  ObjectMapper objectMapper;
    @Autowired
    private PostRequestAuthenticationProvider postRequestAuthenticationProvider;
    @Autowired
    private IdentityCodeAuthenticationProvider identityCodeAuthenticationProvider;
    @Autowired
    private PostRequestAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    private PostRequestAuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private RequestCache requestCache;
    @Autowired
    private SecurityContextLogoutHandler securityContextLogoutHandler;
    @Autowired
    private PasswordEncoder passwordEncoder;
	@Autowired
	private UserDetailsService userDetailsService;
    @Autowired
    private InvalidSessionStrategy invalidSessionStrategy;
    @Autowired
    private SessionInformationExpiredStrategy expiredSessionStrategy;
    @Autowired
    private SessionRegistry sessionRegistry;
    @Autowired
	private CsrfTokenRepository csrfTokenRepository;
    
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
		authcFilter.setFailureCounter(authenticatingFailureCounter);

		authcFilter.setAllowSessionCreation(bizUpcProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
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
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		return authcFilter;
	}
	
    @Bean
    public IdentityCodeAuthenticationProcessingFilter identityCodeAuthenticationProcessingFilter() {
    	
		IdentityCodeAuthenticationProcessingFilter authcFilter = new IdentityCodeAuthenticationProcessingFilter(
				objectMapper);
		
		authcFilter.setAllowSessionCreation(bizUpcProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(bizUpcProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
		if (StringUtils.hasText(bizUpcProperties.getAuthc().getIdentityLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(bizUpcProperties.getAuthc().getIdentityLoginUrlPatterns());
		}
		//authcFilter.setMessageSource(messageSource);
		authcFilter.setMobileParameter(bizUpcProperties.getAuthc().getMobileParameter());
		authcFilter.setCodeParameter(bizUpcProperties.getAuthc().getCodeParameter());
		authcFilter.setPostOnly(bizUpcProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		
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
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(identityCodeAuthenticationProvider)
            .authenticationProvider(postRequestAuthenticationProvider)
        	.userDetailsService(userDetailsService)
        	.passwordEncoder(passwordEncoder);
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
    		.invalidSessionStrategy(invalidSessionStrategy)
    		.invalidSessionUrl(bizUpcProperties.getLogout().getLogoutUrl())
    		.maximumSessions(sessionMgt.getMaximumSessions())
    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
    		.expiredSessionStrategy(expiredSessionStrategy)
			.expiredUrl(bizUpcProperties.getLogout().getLogoutUrl())
			.sessionRegistry(sessionRegistry)
			.and()
    		.sessionAuthenticationErrorUrl(bizUpcProperties.getAuthc().getFailureUrl())
    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
    		.sessionAuthenticationStrategy(sessionStrategy)
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
        	.addFilterBefore(postRequestAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
        	.addFilterBefore(identityCodeAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);  // 不拦截注销
        
        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
 

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
