/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
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
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.AuthenticatingFailureRequestCounter;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProvider;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCorsProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityHeadersProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.boot.biz.property.header.HeaderCacheControlProperties;
import org.springframework.security.boot.biz.property.header.HeaderContentSecurityPolicyProperties;
import org.springframework.security.boot.biz.property.header.HeaderContentTypeOptionsProperties;
import org.springframework.security.boot.biz.property.header.HeaderFeaturePolicyProperties;
import org.springframework.security.boot.biz.property.header.HeaderFrameOptionsProperties;
import org.springframework.security.boot.biz.property.header.HeaderHpkpProperties;
import org.springframework.security.boot.biz.property.header.HeaderHstsProperties;
import org.springframework.security.boot.biz.property.header.HeaderReferrerPolicyProperties;
import org.springframework.security.boot.biz.property.header.HeaderXssProtectionProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.ContentSecurityPolicyConfig;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Web Security Biz Configurer Adapter
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public abstract class WebSecurityBizConfigurerAdapter extends WebSecurityConfigurerAdapter {

	private Pattern rolesPattern = Pattern.compile("roles\\[(\\S+)\\]");
	private Pattern permsPattern = Pattern.compile("perms\\[(\\S+)\\]");
	private Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S+)\\]");
	private final SecurityBizProperties bizProperties;
	private final SecurityAuthcProperties authcProperties;
	private final SecuritySessionMgtProperties sessionMgtProperties;
	private final AuthenticationManager authenticationManager;
	private final List<AuthenticationProvider> authenticationProviders;
	
	public WebSecurityBizConfigurerAdapter(SecurityBizProperties bizProperties, 
			SecurityAuthcProperties authcProperties,
			SecuritySessionMgtProperties sessionMgtProperties,
			List<AuthenticationProvider> authenticationProviders, AuthenticationManager authenticationManager) {
		this.bizProperties = bizProperties;
		this.authcProperties = authcProperties;
		this.sessionMgtProperties = sessionMgtProperties;
		this.authenticationProviders = authenticationProviders;
		this.authenticationManager = authenticationManager;
	}
	
	protected AccessDeniedHandler accessDeniedHandler() {
		AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
		return accessDeniedHandler;
	}
	
	protected AuthenticatingFailureCounter authenticatingFailureCounter() {
		AuthenticatingFailureRequestCounter failureCounter = new AuthenticatingFailureRequestCounter();
		failureCounter.setRetryTimesKeyParameter(authcProperties.getRetry().getRetryTimesKeyParameter());
		return failureCounter;
	}

	protected PostRequestAuthenticationEntryPoint authenticationEntryPoint(
			List<MatchedAuthenticationEntryPoint> entryPoints) {
		PostRequestAuthenticationEntryPoint entryPoint = new PostRequestAuthenticationEntryPoint(
				authcProperties.getPathPattern(), entryPoints);
		entryPoint.setForceHttps(authcProperties.getEntryPoint().isForceHttps());
		entryPoint.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		entryPoint.setUseForward(authcProperties.getEntryPoint().isUseForward());
		return entryPoint;
	}
	
	protected PostRequestAuthenticationFailureHandler authenticationFailureHandler(
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {

		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);

		failureHandler.setAllowSessionCreation(sessionMgtProperties.isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
		failureHandler.setRedirectStrategy(redirectStrategy());
		failureHandler.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		failureHandler.setUseForward(authcProperties.isUseForward());

		return failureHandler;

	}
	
	protected ForwardAuthenticationFailureHandler authenticationFailureForwardHandler(String forwardUrl) {
		return new ForwardAuthenticationFailureHandler(forwardUrl);
	}
	
	protected SimpleUrlAuthenticationFailureHandler authenticationFailureSimpleUrlHandler() {

		SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

		failureHandler.setAllowSessionCreation(sessionMgtProperties.isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
		failureHandler.setRedirectStrategy(redirectStrategy());
		failureHandler.setUseForward(authcProperties.isUseForward());

		return failureHandler;
	}
	
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		AuthenticationManager parentManager = authenticationManager == null ? super.authenticationManagerBean()
				: authenticationManager;
		return parentManager;
	}
	
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		ProviderManager authenticationManager = new ProviderManager(authenticationProviders);
		// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
		authenticationManager.setEraseCredentialsAfterAuthentication(false);
		return authenticationManager;
	}

	public PostRequestAuthenticationProvider authenticationProvider(UserDetailsServiceAdapter userDetailsService,
			PasswordEncoder passwordEncoder) {
		return new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);
	}
	
	protected PostRequestAuthenticationSuccessHandler authenticationSuccessHandler(
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {

		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		successHandler.setAlwaysUseDefaultTargetUrl(authcProperties.isAlwaysUseDefaultTargetUrl());
		successHandler.setDefaultTargetUrl(authcProperties.getSuccessUrl());
		successHandler.setRedirectStrategy(redirectStrategy());
		successHandler.setRequestCache(requestCache());
		successHandler.setStateless(SessionCreationPolicy.STATELESS.equals(sessionMgtProperties.getCreationPolicy()));
		successHandler.setTargetUrlParameter(authcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(authcProperties.isUseReferer());

		return successHandler;
	}


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
		for (AuthenticationProvider authenticationProvider : authenticationProviders) {
			auth.authenticationProvider(authenticationProvider);
		}
	}

	/**
	 * Headers 配置
	 * 
	 * @author ： <a href="https://github.com/hiwepy">wandl</a>
	 * @param http  the HttpSecurity
	 * @param properties the Security Headers Properties
	 * @throws Exception the Exception
	 */
	@SuppressWarnings("rawtypes")
	protected void configure(HttpSecurity http, SecurityHeadersProperties properties) throws Exception {
		if (properties.isEnabled()) {

			HeadersConfigurer<HttpSecurity> headers = http.headers();

			HeaderContentTypeOptionsProperties contentTypeOptions = properties.getContentTypeOptions();
			if (contentTypeOptions.isEnabled()) {
				headers.contentTypeOptions();
			} else {
				headers.contentTypeOptions().disable();
			}

			HeaderXssProtectionProperties xssProtection = properties.getXssProtection();
			if (xssProtection.isEnabled()) {
				headers.xssProtection().xssProtectionEnabled(xssProtection.isEnabled()).block(xssProtection.isBlock());
			} else {
				headers.xssProtection().disable();
			}

			HeaderCacheControlProperties cacheControl = properties.getCacheControl();
			if (cacheControl.isEnabled()) {
				headers.cacheControl();
			} else {
				headers.cacheControl().disable();
			}

			HeaderHstsProperties hsts = properties.getHsts();
			if (hsts.isEnabled()) {
				 headers.httpStrictTransportSecurity()
						.includeSubDomains(hsts.isIncludeSubDomains())
						.maxAgeInSeconds(hsts.getMaxAgeInSeconds());
			} else {
				headers.httpStrictTransportSecurity().disable();
			}

			HeaderFrameOptionsProperties frameOptions = properties.getFrameOptions();
			if (frameOptions.isEnabled()) {
				FrameOptionsConfig config = headers.frameOptions();
				if (frameOptions.isDeny()) {
					config.deny();
				} else if (frameOptions.isSameOrigin()) {
					config.sameOrigin();
				}
			} else {
				headers.frameOptions().disable();
			}

			HeaderHpkpProperties hpkp = properties.getHpkp();
			if (hpkp.isEnabled()) {
				 headers.httpPublicKeyPinning()
						.includeSubDomains(hpkp.isIncludeSubDomains())
						.maxAgeInSeconds(hpkp.getMaxAgeInSeconds())
						.reportOnly(hpkp.isReportOnly())
						.reportUri(hpkp.getReportUri())
						.withPins(hpkp.getPins())
						.addSha256Pins(hpkp.getSha256Pins());
			} else {
				headers.httpPublicKeyPinning().disable();
			}

			HeaderContentSecurityPolicyProperties contentSecurityPolicy = properties.getContentSecurityPolicy();
			if (contentSecurityPolicy.isEnabled()) {
				ContentSecurityPolicyConfig config = headers.contentSecurityPolicy(contentSecurityPolicy.getPolicyDirectives());
				if (contentSecurityPolicy.isReportOnly()) {
					config.reportOnly();
				}
			}

			HeaderReferrerPolicyProperties referrerPolicy = properties.getReferrerPolicy();
			if (referrerPolicy.isEnabled()) {
				headers.referrerPolicy();
			}

			HeaderFeaturePolicyProperties featurePolicy = properties.getFeaturePolicy();
			if (featurePolicy.isEnabled()) {
				headers.featurePolicy(featurePolicy.getPolicyDirectives());
			}

		} else {
			http.headers().cacheControl().disable()// 禁用缓存
					.and().cors();
		}
	}

	/**
	 * CSRF 配置
	 * 
	 * @author ： <a href="https://github.com/hiwepy">wandl</a>
	 * @param http  the HttpSecurity
	 * @param csrf the Security Headers Csrf Properties
	 * @throws Exception the Exception
	 */
	protected void configure(HttpSecurity http, SecurityHeaderCsrfProperties csrf) throws Exception {
		// CSRF 配置
		if (csrf.isEnabled()) {
			http.csrf()
				.csrfTokenRepository(this.csrfTokenRepository())
				.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
		} else {
			http.csrf().disable();
		}
	}

	@Override
	public void configure(WebSecurity web) throws Exception {

		// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet()
				.stream().collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

		List<Entry<String, String>> noneEntries = groupingMap.get("anon");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> {
				return mapper.getKey();
			}).collect(Collectors.toList());
		}
		web.ignoring().antMatchers(permitMatchers.toArray(new String[permitMatchers.size()]))
				.antMatchers(HttpMethod.OPTIONS, "/**");

		super.configure(web);
	}

	protected CorsConfigurationSource configurationSource(SecurityHeaderCorsProperties cors) {

		UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();

		/**
		 * 批量设置参数
		 */
		PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();

		map.from(cors.isAlwaysUseFullPath()).to(configurationSource::setAlwaysUseFullPath);
		map.from(cors.getCorsConfigurations()).to(configurationSource::setCorsConfigurations);
		map.from(cors.isRemoveSemicolonContent()).to(configurationSource::setRemoveSemicolonContent);
		map.from(cors.isUrlDecode()).to(configurationSource::setUrlDecode);

		return configurationSource;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet()
				.stream().collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

		// https://www.jianshu.com/p/01498e0e0c83
		Set<Object> keySet = groupingMap.keySet();
		for (Object key : keySet) {
			// Ant表达式 = roles[xxx]
			Matcher rolesMatcher = rolesPattern.matcher(key.toString());
			if (rolesMatcher.find()) {

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// 角色
				String[] roles = StringUtils.split(rolesMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(roles)) {
					if (roles.length > 1) {
						// 如果用户具备给定角色中的某一个的话，就允许访问
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAnyRole(roles);
					} else {
						// 如果用户具备给定角色的话，就允许访问
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasRole(roles[0]);
					}
				}
			}
			// Ant表达式 = perms[xxx]
			Matcher permsMatcher = permsPattern.matcher(key.toString());
			if (permsMatcher.find()) {

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// 权限标记
				String[] perms = StringUtils.split(permsMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(perms)) {
					if (perms.length > 1) {
						// 如果用户具备给定全权限的某一个的话，就允许访问
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAnyAuthority(perms);
					} else {
						// 如果用户具备给定权限的话，就允许访问
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAuthority(perms[0]);
					}
				}
			}
			// Ant表达式 = ipaddr[192.168.1.0/24]
			Matcher ipMatcher = ipaddrPattern.matcher(key.toString());
			if (rolesMatcher.find()) {

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// ipaddress
				String ipaddr = ipMatcher.group(1);
				if (StringUtils.hasText(ipaddr)) {
					// 如果请求来自给定IP地址的话，就允许访问
					http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
							.hasIpAddress(ipaddr);
				}
			}
		}
	}

	protected void configure(HttpSecurity http, SecurityHeaderCorsProperties cors) throws Exception {
		if (cors.isEnabled()) {
			http.cors().configurationSource(this.configurationSource(cors));
		} else {
			http.cors().disable();
		}
	}

	protected CsrfTokenRepository csrfTokenRepository() {
		// Session 管理器配置参数
		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgtProperties.getFixationPolicy())) {
			return new CookieCsrfTokenRepository();
		}
		return new HttpSessionCsrfTokenRepository();
	}
	
	protected RequestCache requestCache() {
 		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
 		requestCache.setCreateSessionAllowed(sessionMgtProperties.isAllowSessionCreation());
 		requestCache.setSessionAttrName(sessionMgtProperties.getSessionAttrName());
 		return requestCache;
 	}
	
	protected RedirectStrategy redirectStrategy() {
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(authcProperties.getRedirect().isContextRelative());
		return redirectStrategy;
	}
	
	protected LogoutHandler logoutHandler(List<LogoutHandler> logoutHandlers) {
		return new CompositeLogoutHandler(logoutHandlers);
	}

	public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
 		// Session 管理器配置参数
 		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new ChangeSessionIdAuthenticationStrategy();
 		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new SessionFixationProtectionStrategy();
 		} else if (SessionFixationPolicy.NEW_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
 			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
 			return sessionFixationProtectionStrategy;
 		} else {
 			return new NullAuthenticatedSessionStrategy();
 		}
 	}
	
	public SecuritySessionMgtProperties getSessionMgtProperties() {
		return sessionMgtProperties;
	}
	
}
