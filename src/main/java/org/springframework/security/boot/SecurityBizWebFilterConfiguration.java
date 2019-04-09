package org.springframework.security.boot;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.HttpServletRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.HttpServletRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.HttpServletRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.HttpServletRequestUsernamePasswordCaptchaAuthenticationFilter;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration" 
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityBizProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizWebFilterConfiguration implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;

	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;

	/**
	 * 登录监听：实现该接口可监听账号登录失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 * 
	 * @Bean("loginListeners")
	 * 
	 * @ConditionalOnMissingBean(name = "loginListeners") public List<LoginListener>
	 *                                loginListeners() {
	 * 
	 *                                List<LoginListener> loginListeners = new
	 *                                ArrayList<LoginListener>();
	 * 
	 *                                Map<String, LoginListener> beansOfType =
	 *                                getApplicationContext().getBeansOfType(LoginListener.class);
	 *                                if (!ObjectUtils.isEmpty(beansOfType)) {
	 *                                Iterator<Entry<String, LoginListener>> ite =
	 *                                beansOfType.entrySet().iterator(); while
	 *                                (ite.hasNext()) {
	 *                                loginListeners.add(ite.next().getValue()); } }
	 * 
	 *                                return loginListeners; }
	 */

	/**
	 * Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 * 
	 * @Bean("realmListeners")
	 * 
	 * @ConditionalOnMissingBean(name = "realmListeners") public
	 *                                List<PrincipalRealmListener> realmListeners()
	 *                                {
	 * 
	 *                                List<PrincipalRealmListener> realmListeners =
	 *                                new ArrayList<PrincipalRealmListener>();
	 * 
	 *                                Map<String, PrincipalRealmListener>
	 *                                beansOfType =
	 *                                getApplicationContext().getBeansOfType(PrincipalRealmListener.class);
	 *                                if (!ObjectUtils.isEmpty(beansOfType)) {
	 *                                Iterator<Entry<String,
	 *                                PrincipalRealmListener>> ite =
	 *                                beansOfType.entrySet().iterator(); while
	 *                                (ite.hasNext()) {
	 *                                realmListeners.add(ite.next().getValue()); } }
	 * 
	 *                                return realmListeners; }
	 */

	/**
	 * 注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 * 
	 * @Bean("logoutListeners")
	 * 
	 * @ConditionalOnMissingBean(name = "logoutListeners") public
	 *                                List<LogoutListener> logoutListeners() {
	 * 
	 *                                List<LogoutListener> logoutListeners = new
	 *                                ArrayList<LogoutListener>();
	 * 
	 *                                Map<String, LogoutListener> beansOfType =
	 *                                getApplicationContext().getBeansOfType(LogoutListener.class);
	 *                                if (!ObjectUtils.isEmpty(beansOfType)) {
	 *                                Iterator<Entry<String, LogoutListener>> ite =
	 *                                beansOfType.entrySet().iterator(); while
	 *                                (ite.hasNext()) {
	 *                                logoutListeners.add(ite.next().getValue()); }
	 *                                }
	 * 
	 *                                return logoutListeners; }
	 */


	/**
	 * 默认的Session过期过滤器 ：解决Ajax请求期间会话过期异常处理
	 * 
	 * @Bean("sessionExpired")
	 * 
	 * @ConditionalOnMissingBean(name = "sessionExpired") public
	 *                                FilterRegistrationBean<HttpServletSessionExpiredFilter>
	 *                                sessionExpiredFilter(){
	 * 
	 *                                FilterRegistrationBean<HttpServletSessionExpiredFilter>
	 *                                registration = new
	 *                                FilterRegistrationBean<HttpServletSessionExpiredFilter>();
	 *                                registration.setFilter(new
	 *                                HttpServletSessionExpiredFilter());
	 * 
	 *                                registration.setEnabled(false); return
	 *                                registration; }
	 */

	@Bean
	protected BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	public AuthenticationSuccessHandler successHandler() {
		HttpServletRequestAuthenticationSuccessHandler successHandler = new HttpServletRequestAuthenticationSuccessHandler();
		successHandler.setDefaultTargetUrl(bizProperties.getSuccessUrl());
		return successHandler;
	}

	@Bean
	public AuthenticationFailureHandler failureHandler(ObjectMapper mapper) {
		HttpServletRequestAuthenticationFailureHandler failureHandler = new HttpServletRequestAuthenticationFailureHandler(mapper);
		failureHandler.setDefaultFailureUrl(bizProperties.getFailureUrl());
		return failureHandler;
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}

	@Bean
	@ConditionalOnMissingBean
	public AbstractAuthenticationProcessingFilter authenticationFilter(
			AuthenticationManager authenticationManager, 
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, 
			AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			@Autowired(required = false) CaptchaResolver captchaResolver,
			MessageSource messageSource,
			ObjectMapper objectMapper) {
		
		// Form Login With Captcha 
		HttpServletRequestUsernamePasswordCaptchaAuthenticationFilter authcFilter = new HttpServletRequestUsernamePasswordCaptchaAuthenticationFilter(objectMapper);
		
		authcFilter.setCaptchaParameter(bizProperties.getCaptcha().getParamName());
		// 是否验证码必填
		authcFilter.setCaptchaRequired(bizProperties.getCaptcha().isRequired());
		// 登陆失败重试次数，超出限制需要输入验证码
		authcFilter.setRetryTimesWhenAccessDenied(bizProperties.getCaptcha().getRetryTimesWhenAccessDenied());
		// 验证码解析器
		authcFilter.setCaptchaResolver(captchaResolver);
		
		authcFilter.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
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
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint(ObjectMapper objectMapper) {
		
		LoginUrlAuthenticationEntryPoint entryPoint = new HttpServletRequestAuthenticationEntryPoint(bizProperties.getLoginUrl());
		entryPoint.setForceHttps(bizProperties.getAuthc().isForceHttps());
		entryPoint.setUseForward(bizProperties.getAuthc().isUseForward());
		
		return entryPoint;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public LogoutHandler logoutHandler() {
		
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
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLoginUrl(), logoutHandlers.toArray(new LogoutHandler[logoutHandlers.size()]));
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
