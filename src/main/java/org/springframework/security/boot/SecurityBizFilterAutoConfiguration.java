package org.springframework.security.boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.IdentityCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.IdentityCodeAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostUsernamePasswordCaptchaAuthenticationProcessingFilter;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecurityAnonymousProperties;
import org.springframework.security.boot.biz.property.SecurityCorsProperties;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
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
import org.springframework.util.CollectionUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class })
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizFilterAutoConfiguration extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	private Pattern rolesPattern = Pattern.compile("roles\\[(\\S)\\]");
	private Pattern permsPattern = Pattern.compile("perms\\[(\\S)\\]");
	private Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S)\\]");
	
	@Autowired
	private SecurityBizProperties bizProperties;

	@Bean
	public PostUsernamePasswordCaptchaAuthenticationProcessingFilter upcAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager, 
			AuthenticationSuccessHandler successHandler, 
    		AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			@Autowired(required = false) CaptchaResolver captchaResolver,
			MessageSource messageSource,
			ObjectMapper objectMapper) {
		
		// Form Login With Captcha 
		PostUsernamePasswordCaptchaAuthenticationProcessingFilter authcFilter = new PostUsernamePasswordCaptchaAuthenticationProcessingFilter(objectMapper);
		
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
    public IdentityCodeAuthenticationProcessingFilter identityCodeAuthenticationProcessingFilter(
    		AuthenticationManager authenticationManager, 
    		AuthenticationSuccessHandler successHandler, 
    		AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			MessageSource messageSource,
			ObjectMapper objectMapper) {
    	
        IdentityCodeAuthenticationProcessingFilter authcFilter = new IdentityCodeAuthenticationProcessingFilter( objectMapper);
		
		authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setCodeParameter(bizProperties.getAuthc().getCodeParameter());
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getAuthc().getIdentityLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(bizProperties.getAuthc().getIdentityLoginUrlPatterns());
		}
		authcFilter.setMessageSource(messageSource);
		authcFilter.setMobileParameter(bizProperties.getAuthc().getMobileParameter());
		authcFilter.setPostOnly(bizProperties.getAuthc().isPostOnly());
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
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLogoutUrl(), logoutHandlers.toArray(new LogoutHandler[logoutHandlers.size()]));
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}
	
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Autowired
    private PostRequestAuthenticationProvider postRequestAuthenticationProvider;
    @Autowired
    private PostUsernamePasswordCaptchaAuthenticationProcessingFilter upcAuthenticationProcessingFilter;
    @Autowired
    private IdentityCodeAuthenticationProvider identityCodeAuthenticationProvider;
    @Autowired
    private IdentityCodeAuthenticationProcessingFilter identityCodeAuthenticationProcessingFilter;
    @Autowired
    private PostRequestAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    private PostRequestAuthenticationFailureHandler authenticationFailureHandler;
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
    private SessionAuthenticationStrategy sessionStrategy;
    @Autowired
    private SessionRegistry sessionRegistry;
   
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
    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
    	// Session 注销配置参数
    	SecurityLogoutProperties logout = bizProperties.getLogout();
    	// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet().stream()
				.collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));
    	

		ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry
			registry = http.authorizeRequests();
		
		
		List<Entry<String, String>> noneEntries = groupingMap.get("anon");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> {
				return mapper.getKey();
			}).collect(Collectors.toList());
		}
		// 登录地址不拦截 
		permitMatchers.add(bizProperties.getAuthc().getLoginUrlPatterns());
		
		//添加不需要认证的路径 
		registry.antMatchers(permitMatchers.toArray(new String[permitMatchers.size()])).permitAll();
		
		// https://www.jianshu.com/p/01498e0e0c83
		Set<Object> keySet = groupingMap.keySet();
		for (Object key : keySet) {
			// Ant表达式 = roles[xxx] 
			Matcher rolesMatcher = rolesPattern.matcher(key.toString());
			if (rolesMatcher.find()) {
				
				System.out.println("Found value: " + rolesMatcher.group(0));
				System.out.println("Found value: " + rolesMatcher.group(1));

				List<String> matchers = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// 角色
				String[] roles = StringUtils.split(rolesMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(roles)) {
					if (roles.length > 1) {
						// 如果用户具备给定角色中的某一个的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasAnyRole(roles);
					} else {
						// 如果用户具备给定角色的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasRole(roles[0]);
					}
				}
			}
			// Ant表达式 = perms[xxx] 
			Matcher permsMatcher = permsPattern.matcher(key.toString());
			if (permsMatcher.find()) {
				
				System.out.println("Found value: " + permsMatcher.group(0));
				System.out.println("Found value: " + permsMatcher.group(1));

				List<String> matchers = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// 权限标记
				String[] perms = StringUtils.split(permsMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(perms)) {
					if (perms.length > 1) {
						// 如果用户具备给定全权限的某一个的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasAnyAuthority(perms);
					} else {
						// 如果用户具备给定权限的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasAuthority(perms[0]);
					}
				}
			}
			// Ant表达式 = ipaddr[192.168.1.0/24] 
			Matcher ipMatcher = ipaddrPattern.matcher(key.toString());
			if (rolesMatcher.find()) {
				
				System.out.println("Found value: " + ipMatcher.group(0));
				System.out.println("Found value: " + ipMatcher.group(1));

				List<String> matchers = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// ipaddress
				String ipaddr = rolesMatcher.group(1);
				if (StringUtils.hasText(ipaddr)) {
					// 如果请求来自给定IP地址的话，就允许访问
					registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasIpAddress(ipaddr);
				}
			}
		}
		
		//允许认证过的用户访问
		registry.anyRequest().authenticated();
		
	    // Session 管理器配置
    	http.sessionManagement()
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
        	.addFilterBefore(upcAuthenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class)
        	.addFilterBefore(identityCodeAuthenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class);  // 不拦截注销
        
        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
 
        // 匿名登录配置
        SecurityAnonymousProperties anonymous = bizProperties.getAnonymous();
        if(anonymous.isEnabled()) {
        	//允许匿名用户访问
        	http.anonymous();
        } else {
        	http.anonymous().disable();
        }
        // CORS 配置
       	SecurityCorsProperties cors = bizProperties.getCors();
       	if(cors.isEnabled()) {
       		http.cors()
       				   //.configurationSource(configurationSource)
       				   .and();
        } else {
        	http.cors().disable();
        }
       	// CSRF 配置
    	SecurityCsrfProperties csrf = bizProperties.getCsrf();
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
    public void configure(WebSecurity web) throws Exception {
    	
    	// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet().stream()
				.collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));
    	
		List<Entry<String, String>> noneEntries = groupingMap.get("anon");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> {
				return mapper.getKey();
			}).collect(Collectors.toList());
		}
		// 登录地址不拦截 
		permitMatchers.add(bizProperties.getAuthc().getLoginUrlPatterns());
		
    	web.ignoring().antMatchers(permitMatchers.toArray(new String[permitMatchers.size()]));
    	
    	//web.httpFirewall(httpFirewall)
    	
    }
	
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
