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

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.BeansException;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.CustomWebSecurityExpressionHandler;
import org.springframework.security.boot.biz.property.SecurityHeaderCorsProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityHeadersProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.header.*;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.ContentSecurityPolicyConfig;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * WebSecurityCustomizer Adapter
 * @see WebSecurityCustomizer
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public abstract   class WebSecurityCustomizerAdapter implements WebSecurityCustomizer, ApplicationContextAware {

	protected Pattern rolesPattern = Pattern.compile("roles\\[(\\S+)\\]");
	protected Pattern permsPattern = Pattern.compile("perms\\[(\\S+)\\]");
	protected Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S+)\\]");
	protected final SecurityBizProperties bizProperties;
	protected final SecuritySessionMgtProperties sessionMgtProperties;
	protected final List<AuthenticationProvider> authenticationProviders;
	protected ApplicationContext applicationContext;

	public WebSecurityCustomizerAdapter(SecurityBizProperties bizProperties,
										SecuritySessionMgtProperties sessionMgtProperties,
										List<AuthenticationProvider> authenticationProviders) {
		this.bizProperties = bizProperties;
		this.sessionMgtProperties = sessionMgtProperties;
		this.authenticationProviders = authenticationProviders;
	}

	public AuthenticationManager authenticationManagerBean() throws Exception {
		ProviderManager authenticationManager = new ProviderManager(authenticationProviders);
		// 不擦除认证密码，擦除会导致TokenBasedRememberMeServices因为找不到Credentials再调用UserDetailsService而抛出UsernameNotFoundException
		authenticationManager.setEraseCredentialsAfterAuthentication(false);
		return authenticationManager;
	}
	
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
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
				.csrfTokenRepository(WebSecurityUtils.csrfTokenRepository(sessionMgtProperties))
				.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()));
		} else {
			http.csrf().disable();
		}
	}

	@Override
	public void customize(WebSecurity web) {

		// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet()
				.stream().collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

		List<Entry<String, String>> noneEntries = groupingMap.get("anon");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> mapper.getKey()).collect(Collectors.toList());
		}
		web.ignoring()
				.antMatchers(permitMatchers.toArray(new String[permitMatchers.size()]))
				.antMatchers(HttpMethod.OPTIONS, "/**");

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
						http = http.authorizeRequests()
								.expressionHandler(customWebSecurityExpressionHandler())
								.antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAnyRole(roles).and();
					} else {
						// 如果用户具备给定角色的话，就允许访问
						http = http.authorizeRequests()
								.expressionHandler(customWebSecurityExpressionHandler())
								.antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasRole(roles[0]).and();
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
						http = http.authorizeRequests()
								.expressionHandler(customWebSecurityExpressionHandler())
								.antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAnyAuthority(perms).and();
					} else {
						// 如果用户具备给定权限的话，就允许访问
						http = http.authorizeRequests()
								.expressionHandler(customWebSecurityExpressionHandler())
								.antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAuthority(perms[0]).and();
					}
				}
			}
			// Ant表达式 = ipaddr[192.168.1.0/24]
			Matcher ipMatcher = ipaddrPattern.matcher(key.toString());
			if (ipMatcher.find()) {

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// ipaddress
				String ipaddr = ipMatcher.group(1);
				if (StringUtils.hasText(ipaddr)) {
					// 如果请求来自给定IP地址的话，就允许访问
					http = http.authorizeRequests()
							.expressionHandler(customWebSecurityExpressionHandler())
							.antMatchers(antPatterns.toArray(new String[antPatterns.size()]))
							.hasIpAddress(ipaddr).and();
				}
			}
		}
	}

	public SecurityExpressionHandler<FilterInvocation> customWebSecurityExpressionHandler() {
		return new CustomWebSecurityExpressionHandler();
	}

	protected void configure(HttpSecurity http, SecurityHeaderCorsProperties cors) throws Exception {
		if (cors.isEnabled()) {
			http.cors().configurationSource(this.configurationSource(cors));
		} else {
			http.cors().disable();
		}
	}
	
	public SecuritySessionMgtProperties getSessionMgtProperties() {
		return sessionMgtProperties;
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
