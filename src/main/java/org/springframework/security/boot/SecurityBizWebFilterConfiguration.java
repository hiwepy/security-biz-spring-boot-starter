package org.springframework.security.boot;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareLoginProcessingFilter;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration" 
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityBizProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

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
	@ConditionalOnMissingBean
	public AuthenticationSuccessHandler successHandler() {
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			return new AjaxAwareAuthenticationSuccessHandler(bizProperties.getSuccessUrl());
		}
		// Form Login
		else {
			SimpleUrlAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setDefaultTargetUrl(bizProperties.getSuccessUrl());
			return successHandler;
		}
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationFailureHandler failureHandler() {
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			return new AjaxAwareAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
		// Form Login
		else {
			return new SimpleUrlAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
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
	public AbstractAuthenticationProcessingFilter authenticationFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, 
			ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, 
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy) {
		
		UsernamePasswordAuthenticationFilter authenticationFilter = null;
		
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			authenticationFilter = new AjaxAwareLoginProcessingFilter();
		} 
		// Form Login
		else {
			authenticationFilter = new UsernamePasswordAuthenticationFilter();
		}
		authenticationFilter.setAllowSessionCreation(bizProperties.isAllowSessionCreation());
		authenticationFilter.setApplicationEventPublisher(publisher);
		authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authenticationFilter.setAuthenticationFailureHandler(failureHandler);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		authenticationFilter.setAuthenticationSuccessHandler(successHandler);
		authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authenticationFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
		}
		// authenticationFilter.setMessageSource(messageSource);
		authenticationFilter.setPasswordParameter(bizProperties.getPasswordParameter());
		authenticationFilter.setPostOnly(bizProperties.isPostOnly());
		authenticationFilter.setRememberMeServices(rememberMeServices);
		authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authenticationFilter.setUsernameParameter(bizProperties.getUsernameParameter());

		return authenticationFilter;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		
		LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint(bizProperties.getLoginUrl());
		entryPoint.setForceHttps(bizProperties.isForceHttps());
		entryPoint.setUseForward(bizProperties.isUseForward());
		
		return entryPoint;
	}
	
	/**
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean
	public LogoutFilter logoutFilter() {
		// 登录注销后的重定向地址：直接进入登录页面
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLoginUrl(), new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}

	/*@Bean
	public FilterRegistrationBean<HttpParamsFilter> httpParamsFilter() {
		FilterRegistrationBean<HttpParamsFilter> filterRegistrationBean = new FilterRegistrationBean<HttpParamsFilter>();
		filterRegistrationBean.setFilter(new HttpParamsFilter());
		filterRegistrationBean.setOrder(-999);
		filterRegistrationBean.addUrlPatterns("/");
		return filterRegistrationBean;
	}*/

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
