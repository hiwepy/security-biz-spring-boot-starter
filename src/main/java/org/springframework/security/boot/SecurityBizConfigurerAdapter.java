/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
import org.springframework.http.HttpMethod;
import org.springframework.security.boot.biz.property.SecurityHeaderCrosProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityHeadersProperties;
import org.springframework.security.boot.biz.property.header.HeaderCacheControlProperties;
import org.springframework.security.boot.biz.property.header.HeaderContentSecurityPolicyProperties;
import org.springframework.security.boot.biz.property.header.HeaderContentTypeOptionsProperties;
import org.springframework.security.boot.biz.property.header.HeaderFeaturePolicyProperties;
import org.springframework.security.boot.biz.property.header.HeaderFrameOptionsProperties;
import org.springframework.security.boot.biz.property.header.HeaderHpkpProperties;
import org.springframework.security.boot.biz.property.header.HeaderHstsProperties;
import org.springframework.security.boot.biz.property.header.HeaderReferrerPolicyProperties;
import org.springframework.security.boot.biz.property.header.HeaderXssProtectionProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.ContentSecurityPolicyConfig;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public abstract class SecurityBizConfigurerAdapter extends WebSecurityConfigurerAdapter {

	private Pattern rolesPattern = Pattern.compile("roles\\[(\\S+)\\]");
	private Pattern permsPattern = Pattern.compile("perms\\[(\\S+)\\]");
	private Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S+)\\]");
	private final SecurityBizProperties bizProperties;
	private CsrfTokenRepository csrfTokenRepository;
	private CorsConfigurationSource configurationSource;
	 
	public SecurityBizConfigurerAdapter(SecurityBizProperties bizProperties, 
			CsrfTokenRepository csrfTokenRepository,
			CorsConfigurationSource configurationSource) {
		this.bizProperties = bizProperties;
		this.csrfTokenRepository = csrfTokenRepository;
		this.configurationSource = configurationSource;
	}
 
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
	}
	
	/**
	 * CSRF 配置
	 * @author 		： <a href="https://github.com/vindell">wandl</a>
	 * @param http
	 * @param csrf
	 * @throws Exception
	 */
	protected void configure(HttpSecurity http, SecurityHeaderCsrfProperties csrf) throws Exception {
		// CSRF 配置
    	if(csrf.isEnabled()) {
       		http.csrf()
			   	.csrfTokenRepository(csrfTokenRepository)
			   	.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        } else {
        	http.csrf().disable();
        }
	    	
    	if(csrf.isEnabled()) {
       		http.csrf()
			   	.csrfTokenRepository(csrfTokenRepository)
			   	.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.and()
				.headers()
				.frameOptions().sameOrigin()
				.xssProtection()
				.block(true);
        } else {
        	http.csrf().disable();
        }
	}
	
	/**
	 * Headers 配置
	 * @author 		： <a href="https://github.com/vindell">wandl</a>
	 * @param http
	 * @param headers
	 * @throws Exception
	 */
	@SuppressWarnings("rawtypes")
	protected void configure(HttpSecurity http, SecurityHeadersProperties properties) throws Exception{
    	if(properties.isEnabled()) {

    		HeadersConfigurer<HttpSecurity> headers = http.headers();
    		
    		HeaderContentTypeOptionsProperties contentTypeOptions = properties.getContentTypeOptions();
    		if(contentTypeOptions.isEnabled()) {
    			headers.contentTypeOptions();
    		} else {
    			headers.contentTypeOptions().disable();
			}
    		
    		HeaderXssProtectionProperties xssProtection = properties.getXssProtection();
    		if(xssProtection.isEnabled()) {
    			headers.xssProtection()
		            .xssProtectionEnabled(xssProtection.isEnabled())
		            .block(xssProtection.isBlock());
    		} else {
    			headers.xssProtection().disable();
			}
    		
    		HeaderCacheControlProperties cacheControl = properties.getCacheControl();
    		if(cacheControl.isEnabled()) {
    			headers.cacheControl();
    		} else {
    			headers.cacheControl().disable();
			}

    		HeaderHstsProperties hsts = properties.getHsts();
    		if(hsts.isEnabled()) {
    			headers.httpStrictTransportSecurity()
			            .includeSubDomains(hsts.isIncludeSubDomains())
			            .maxAgeInSeconds(hsts.getMaxAgeInSeconds());
    		} else {
    			headers.httpStrictTransportSecurity().disable();
			}
    		
    		HeaderFrameOptionsProperties frameOptions = properties.getFrameOptions();
    		if(frameOptions.isEnabled()) {
    			FrameOptionsConfig config = headers.frameOptions();
    			if(frameOptions.isDeny()) {
    				config.deny();
    			} else if (frameOptions.isSameOrigin()) {
    				config.sameOrigin();
				}
    		} else {
    			headers.frameOptions().disable();
			}
    		
    		HeaderHpkpProperties hpkp = properties.getHpkp();
    		if(hpkp.isEnabled()) {
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
    		if(contentSecurityPolicy.isEnabled()) {
    			ContentSecurityPolicyConfig config = headers.contentSecurityPolicy(contentSecurityPolicy.getPolicyDirectives());
    			if(contentSecurityPolicy.isReportOnly()) {
    				config.reportOnly();
    			}
			}
    		
    		HeaderReferrerPolicyProperties referrerPolicy = properties.getReferrerPolicy();
    		if(referrerPolicy.isEnabled()) {
    			headers.referrerPolicy();
			}
    		
    		HeaderFeaturePolicyProperties featurePolicy = properties.getFeaturePolicy();
    		if(featurePolicy.isEnabled()) {
    			headers.featurePolicy(featurePolicy.getPolicyDirectives());
			}
	           
    	} else {
    		http.headers()
    			.cacheControl().disable()// 禁用缓存
    			.and()
    			.cors(); 
    	}
	}
	
	/**
	 * Cros 配置
	 * @author 		： <a href="https://github.com/vindell">wandl</a>
	 * @param http
	 * @param cros
	 * @throws Exception
	 */
	protected void configure(HttpSecurity http, SecurityHeaderCrosProperties cros) throws Exception {
    	if(cros.isEnabled()) {
    		http.cors().configurationSource(configurationSource);
    	} else {
    		http.cors().disable(); 
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

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// 角色
				String[] roles = StringUtils.split(rolesMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(roles)) {
					if (roles.length > 1) {
						// 如果用户具备给定角色中的某一个的话，就允许访问
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasAnyRole(roles);
					} else {
						// 如果用户具备给定角色的话，就允许访问
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasRole(roles[0]);
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
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasAnyAuthority(perms);
					} else {
						// 如果用户具备给定权限的话，就允许访问
						http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasAuthority(perms[0]);
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
					http.authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasIpAddress(ipaddr);
				}
			}
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
		web.ignoring()
			.antMatchers(permitMatchers.toArray(new String[permitMatchers.size()]))
			.antMatchers(HttpMethod.OPTIONS, "/**");
		
		super.configure(web);
	}
	
}
