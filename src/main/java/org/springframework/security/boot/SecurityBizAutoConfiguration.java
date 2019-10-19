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

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.AuthorizationPermissionEvaluator;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
import org.springframework.util.CollectionUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityBizUpcProperties.class })
public class SecurityBizAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
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
	public RequestCache requestCache(SecurityBizProperties bizProperties) {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setCreateSessionAllowed(bizProperties.getSessionMgt().isAllowSessionCreation());
		requestCache.setSessionAttrName(bizProperties.getSessionMgt().getSessionAttrName());
		// requestCache.setRequestMatcher(requestMatcher);
		// requestCache.setSessionAttrName(sessionAttrName);
		return requestCache;
	}

	@Bean
	@ConditionalOnMissingBean
	public RedirectStrategy redirectStrategy(SecurityBizProperties bizProperties) {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(bizProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionInformationExpiredStrategy sessionInformationExpiredStrategy(SecurityBizProperties bizProperties,
			RedirectStrategy redirectStrategy) {
		return new SimpleRedirectSessionInformationExpiredStrategy(bizProperties.getSessionMgt().getFailureUrl(),
				redirectStrategy);
	}

	@Bean
	@ConditionalOnMissingBean
	public InvalidSessionStrategy invalidSessionStrategy(SecurityBizProperties bizProperties) {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				bizProperties.getSessionMgt().getFailureUrl());
		invalidSessionStrategy.setCreateNewSession(bizProperties.getSessionMgt().isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionAuthenticationStrategy(SecurityBizProperties bizProperties) {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgt.getFixationPolicy())) {
			return new ChangeSessionIdAuthenticationStrategy();
		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(sessionMgt.getFixationPolicy())) {
			return new SessionFixationProtectionStrategy();
		} else if (SessionFixationPolicy.NEW_SESSION.equals(sessionMgt.getFixationPolicy())) {
			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
			return sessionFixationProtectionStrategy;
		} else {
			return new NullAuthenticatedSessionStrategy();
		}
	}
	
	@Bean
	@ConditionalOnMissingBean
	public CsrfTokenRepository csrfTokenRepository(SecurityBizProperties bizProperties) {
		// Session 管理器配置参数
		SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgt.getFixationPolicy())) {
			return new CookieCsrfTokenRepository();
		}
		return new HttpSessionCsrfTokenRepository();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public PostRequestAuthenticationEntryPoint postRequestAuthenticationEntryPoint(SecurityBizProperties bizProperties,
			@Autowired(required = false) List<MatchedAuthenticationEntryPoint> entryPoints) {

		PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint("/login", entryPoints);
		entryPoint.setForceHttps(bizProperties.getEntryPoint().isForceHttps());
		entryPoint.setStateless(bizProperties.isStateless());
		entryPoint.setUseForward(bizProperties.getEntryPoint().isUseForward());

		return entryPoint;
	}

	@Bean
	public PostRequestAuthenticationFailureHandler authenticationFailureHandler(
			SecurityBizProperties bizProperties,
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationFailureHandler> failureHandlers, 
			RedirectStrategy redirectStrategy) {
		
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);
		
		failureHandler.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(bizProperties.getSessionMgt().getFailureUrl());
		failureHandler.setRedirectStrategy(redirectStrategy);
		failureHandler.setStateless(bizProperties.isStateless());
		failureHandler.setUseForward(bizProperties.getSessionMgt().isUseForward());
		
		return failureHandler;
		
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AuthenticatingFailureCounter authenticatingFailureCounter(SecurityBizProperties bizProperties) {
		AuthenticatingFailureRequestCounter failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(bizProperties.getRetry().getRetryTimesKeyParameter());
		return failureCounter;
	}
	
	@Configuration
	@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class })
	@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityBizUpcProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER)
	static class BizWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		private Pattern rolesPattern = Pattern.compile("roles\\[(\\S+)\\]");
		private Pattern permsPattern = Pattern.compile("perms\\[(\\S+)\\]");
		private Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S+)\\]");
		private final SecurityBizProperties bizProperties;
		private final SecurityBizUpcProperties bizUpcProperties;
		private final PostRequestAuthenticationEntryPoint authenticationEntryPoint;
		private final List<SecurityBizConfigurerAdapter> securityBizConfigurerAdapters;
		
		public BizWebSecurityConfigurerAdapter(
				ObjectProvider<PostRequestAuthenticationEntryPoint> authenticationEntryPointProvider,
				ObjectProvider<SecurityBizConfigurerAdapter> securityBizConfigurerAdapterProvider,
				SecurityBizProperties bizProperties, SecurityBizUpcProperties bizUpcProperties) {

			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable();

			this.bizProperties = bizProperties;
			this.bizUpcProperties = bizUpcProperties;
			this.securityBizConfigurerAdapters = securityBizConfigurerAdapterProvider.orderedStream().collect(Collectors.toList());
			
		}

		@Override
		@Bean
		public AuthenticationManager authenticationManagerBean() throws Exception {
			Map<String, AuthenticationProvider> providerMap = getApplicationContext()
					.getBeansOfType(AuthenticationProvider.class);
			if (CollectionUtils.isEmpty(providerMap)) {
				return super.authenticationManagerBean();
			}

			ProviderManager authenticationManager = new ProviderManager(
					providerMap.values().stream().collect(Collectors.toList()), super.authenticationManagerBean());
			// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
			authenticationManager.setEraseCredentialsAfterAuthentication(false);

			return authenticationManager;
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			super.configure(auth);
			// 批量处理其他逻辑
			for (SecurityBizConfigurerAdapter configurerAdapter : securityBizConfigurerAdapters) {
				configurerAdapter.configure(auth);
			}
		}
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {

			// 对过滤链按过滤器名称进行分组
			Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap()
					.entrySet().stream()
					.collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

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
							http.authorizeRequests().antMatchers(matchers.toArray(new String[matchers.size()])).hasAnyRole(roles);
						} else {
							// 如果用户具备给定角色的话，就允许访问
							http.authorizeRequests().antMatchers(matchers.toArray(new String[matchers.size()])).hasRole(roles[0]);
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
							http.authorizeRequests().antMatchers(matchers.toArray(new String[matchers.size()])).hasAnyAuthority(perms);
						} else {
							// 如果用户具备给定权限的话，就允许访问
							http.authorizeRequests().antMatchers(matchers.toArray(new String[matchers.size()])).hasAuthority(perms[0]);
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
						http.authorizeRequests().antMatchers(matchers.toArray(new String[matchers.size()])).hasIpAddress(ipaddr);
					}
				}
			}
			
			http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);

			// 批量处理其他逻辑
			for (SecurityBizConfigurerAdapter configurerAdapter : securityBizConfigurerAdapters) {
				configurerAdapter.configure(http);
			}
			
		}

		@Override
		public void configure(WebSecurity web) throws Exception {
			// 对过滤链按过滤器名称进行分组
			Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap()
					.entrySet().stream()
					.collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

			List<Entry<String, String>> noneEntries = groupingMap.get("anon");
			List<String> permitMatchers = new ArrayList<String>();
			if (!CollectionUtils.isEmpty(noneEntries)) {
				permitMatchers = noneEntries.stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
			}
			// 登录地址不拦截
			permitMatchers.add(bizUpcProperties.getAuthc().getPathPattern());

			web.ignoring()
				.antMatchers(permitMatchers.toArray(new String[permitMatchers.size()]))
				.antMatchers(HttpMethod.OPTIONS, "/**");
			
			// 批量处理其他逻辑
			for (SecurityBizConfigurerAdapter configurerAdapter : securityBizConfigurerAdapters) {
				configurerAdapter.configure(web);
			}
		}

	}

}
