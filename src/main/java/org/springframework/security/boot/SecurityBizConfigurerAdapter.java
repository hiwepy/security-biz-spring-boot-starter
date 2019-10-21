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
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.util.CollectionUtils;

/**
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public abstract class SecurityBizConfigurerAdapter extends WebSecurityConfigurerAdapter {

	private Pattern rolesPattern = Pattern.compile("roles\\[(\\S+)\\]");
	private Pattern permsPattern = Pattern.compile("perms\\[(\\S+)\\]");
	private Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S+)\\]");
	private final SecurityBizProperties bizProperties;
	
	public SecurityBizConfigurerAdapter(SecurityBizProperties bizProperties) {
		this.bizProperties = bizProperties;
	}
 
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
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
						for (String antPattern : antPatterns) {
							// 如果用户具备给定角色中的某一个的话，就允许访问
							http.antMatcher(antPattern).authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasAnyRole(roles);
						}
					} else {
						for (String antPattern : antPatterns) {
							// 如果用户具备给定角色的话，就允许访问
							http.antMatcher(antPattern).authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasRole(roles[0]);
						}
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
						for (String antPattern : antPatterns) {
							// 如果用户具备给定全权限的某一个的话，就允许访问
							http.antMatcher(antPattern).authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasAnyAuthority(perms);
						}
					} else {
						for (String antPattern : antPatterns) {
							// 如果用户具备给定权限的话，就允许访问
							http.antMatcher(antPattern).authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasAuthority(perms[0]);
						}
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
					for (String antPattern : antPatterns) {
						// 如果请求来自给定IP地址的话，就允许访问
						http.antMatcher(antPattern).authorizeRequests().antMatchers(antPatterns.toArray(new String[antPatterns.size()])).hasIpAddress(ipaddr);
					}
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
	}
	
}
