package org.springframework.security.boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.MobileCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.MobileCodeAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.UsernamePasswordCaptchaAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecurityAnonymousProperties;
import org.springframework.security.boot.biz.property.SecurityCorsProperties;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfigurationSource;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration" 
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityBizProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizFilterAutoConfiguration extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;

	@Autowired
	private SecurityBizProperties bizProperties;
	

	@Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}
    
	@Bean
	public PostRequestAuthenticationSuccessHandler postRequestAuthenticationSuccessHandler(@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			RedirectStrategy redirectStrategy, RequestCache requestCache) {
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(authenticationListeners, bizProperties.getSuccessUrl());
		successHandler.setRedirectStrategy(redirectStrategy);
		successHandler.setRequestCache(requestCache);
		successHandler.setTargetUrlParameter(bizProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(bizProperties.getAuthc().isUseReferer());
		return successHandler;
	}
	
	@Bean
	public PostRequestAuthenticationFailureHandler postRequestAuthenticationFailureHandler(@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			RedirectStrategy redirectStrategy) {
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(authenticationListeners, bizProperties.getFailureUrl());
		failureHandler.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setUseForward(bizProperties.getAuthc().isUseForward());
		return failureHandler;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint() {
		
		LoginUrlAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint(bizProperties.getAuthc().getLoginUrl());
		entryPoint.setForceHttps(bizProperties.getAuthc().isForceHttps());
		entryPoint.setUseForward(bizProperties.getAuthc().isUseForward());
		
		return entryPoint;
	}

	@Bean
	public UsernamePasswordCaptchaAuthenticationProcessingFilter upcAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager, 
			AuthenticationSuccessHandler successHandler, 
			AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			@Autowired(required = false) CaptchaResolver captchaResolver,
			MessageSource messageSource,
			ObjectMapper objectMapper) {
		
		// Form Login With Captcha 
		UsernamePasswordCaptchaAuthenticationProcessingFilter authcFilter = new UsernamePasswordCaptchaAuthenticationProcessingFilter(objectMapper);
		
		authcFilter.setCaptchaParameter(bizProperties.getCaptcha().getParamName());
		// 是否验证码必填
		authcFilter.setCaptchaRequired(bizProperties.getCaptcha().isRequired());
		// 登陆失败重试次数，超出限制需要输入验证码
		authcFilter.setRetryTimesWhenAccessDenied(bizProperties.getCaptcha().getRetryTimesWhenAccessDenied());
		// 验证码解析器
		authcFilter.setCaptchaResolver(captchaResolver);
		
		authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getAuthc().getLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(bizProperties.getAuthc().getLoginUrlPatterns());
		}
		authcFilter.setMessageSource(messageSource);
		authcFilter.setPasswordParameter(bizProperties.getAuthc().getPasswordParameter());
		authcFilter.setPostOnly(bizProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authcFilter.setUsernameParameter(bizProperties.getAuthc().getUsernameParameter());

		return authcFilter;
	}
	
    @Bean
    public MobileCodeAuthenticationProcessingFilter mobileCodeAuthenticationProcessingFilter(
    		AuthenticationManager authenticationManager, 
			AuthenticationSuccessHandler successHandler, 
			AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			MessageSource messageSource,
			ObjectMapper objectMapper) {
    	
        MobileCodeAuthenticationProcessingFilter authcFilter = new MobileCodeAuthenticationProcessingFilter();
		
		authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setCodeParameter(bizProperties.getAuthc().getCodeParameter());
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getAuthc().getMobileLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(bizProperties.getAuthc().getMobileLoginUrlPatterns());
		}
		authcFilter.setMessageSource(messageSource);
		authcFilter.setMobileParameter(bizProperties.getAuthc().getMobileParameter());
		authcFilter.setPostOnly(bizProperties.getAuthc().isPostOnly());
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
		
        return authcFilter;
    }
    
	@Bean
	public SecurityContextLogoutHandler securityContextLogoutHandler() {
		
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setClearAuthentication(bizProperties.getLogout().isClearAuthentication());
		logoutHandler.setInvalidateHttpSession(bizProperties.getLogout().isInvalidateHttpSession());
		
		return logoutHandler;
	}
	
	/*
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean 
	public LogoutFilter logoutFilter(List<LogoutHandler> logoutHandlers) {
		// 登录注销后的重定向地址：直接进入登录页面
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLogoutUrl(), logoutHandlers.toArray(new LogoutHandler[logoutHandlers.size()]));
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}
	
	private CorsConfigurationSource configurationSource;
	
	
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
 
    @Autowired
    private PostRequestAuthenticationSuccessHandler postRequestAuthenticationSuccessHandler;
    @Autowired
    private PostRequestAuthenticationFailureHandler postRequestAuthenticationFailureHandler;
    @Autowired
    private PostRequestAuthenticationProvider postRequestAuthenticationProvider;
    @Autowired
    private MobileCodeAuthenticationProvider mobileCodeAuthenticationProvider;
    @Autowired
    private UsernamePasswordCaptchaAuthenticationProcessingFilter upcAuthenticationProcessingFilter;
    @Autowired
    private MobileCodeAuthenticationProcessingFilter mobileCodeAuthenticationProcessingFilter;
    @Autowired
    private LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint;
    @Autowired
    private RequestCache requestCache;
    @Autowired
    private SecurityContextLogoutHandler securityContextLogoutHandler;
    @Autowired
    private CsrfTokenRepository csrfTokenRepository;
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
  
	
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(mobileCodeAuthenticationProvider)
            .authenticationProvider(postRequestAuthenticationProvider)
        	.userDetailsService(userDetailsService)
        	.passwordEncoder(passwordEncoder);
    }
    
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
    	// Session 管理器配置参数
    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
    	// Session 注销配置参数
    	SecurityLogoutProperties logout = bizProperties.getLogout();
    	// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getChainDefinitionMap().entrySet().stream()
				.collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));
    	
		List<Entry<String, String>> noneEntries = groupingMap.get("none");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> {
				return mapper.getKey();
			}).collect(Collectors.toList());
		}
		// 登录地址不拦截 
		permitMatchers.add(bizProperties.getAuthc().getLoginUrlPatterns());
		
		// role[rr,xxx,xxx]
		
    	http.authorizeRequests()
    		//添加不需要认证的路径 
    		.antMatchers(permitMatchers.toArray(new String[permitMatchers.size()])).permitAll()
    		.antMatchers("").authenticated()
    		.antMatchers("").hasAnyRole("")
    		.anyRequest().fullyAuthenticated()
	    	// Session 管理器配置
    		.and()
    		.sessionManagement()
    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
    		.invalidSessionStrategy(invalidSessionStrategy)
    		.invalidSessionUrl(bizProperties.getLogoutUrl())
    		.maximumSessions(sessionMgt.getMaximumSessions())
    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
    		.expiredSessionStrategy(expiredSessionStrategy)
			.expiredUrl(bizProperties.getLogoutUrl())
			.sessionRegistry(sessionRegistry)
			.and()
    		.sessionAuthenticationErrorUrl(bizProperties.getFailureUrl())
    		.sessionAuthenticationFailureHandler(postRequestAuthenticationFailureHandler)
    		.sessionCreationPolicy(sessionMgt.getSessionPolicy())
    		// Session 注销配置
    		.and()
    		.logout()
        	.addLogoutHandler(securityContextLogoutHandler)
        	.clearAuthentication(true)
        	.permitAll()
        	// Request 缓存配置
        	.and()
    		.requestCache()
		        	.requestCache(requestCache)
		        	.and()
		        	.addFilterBefore(upcAuthenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class)
		        	.addFilterBefore(mobileCodeAuthenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class);  // 不拦截注销
        
        http.exceptionHandling().authenticationEntryPoint(loginUrlAuthenticationEntryPoint);
 
        // 匿名登录配置
        SecurityAnonymousProperties anonymous = bizProperties.getAnonymous();
        if(anonymous.isEnabled()) {
        	http = http.anonymous().and();
        } else {
        	http = http.anonymous().disable();
        }
        // CORS 配置
       	SecurityCorsProperties cors = bizProperties.getCors();
       	if(cors.isEnabled()) {
       		http = http.cors()
       				   .configurationSource(configurationSource)
       				   .and();
        } else {
        	http = http.cors().disable();
        }
       	// CSRF 配置
    	SecurityCsrfProperties csrf = bizProperties.getCsrf();
    	if(csrf.isEnabled()) {
       		http = http.csrf()
       				   .csrfTokenRepository(csrfTokenRepository)
       				   .ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
       				   .and();
        } else {
        	http = http.csrf().disable();
        }
 
    }
	
	
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
