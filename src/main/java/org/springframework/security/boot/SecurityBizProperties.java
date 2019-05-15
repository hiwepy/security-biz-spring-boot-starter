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

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityEntryPointProperties;

@ConfigurationProperties(SecurityBizProperties.PREFIX)
public class SecurityBizProperties {

	public static final String PREFIX = "spring.security";
	
	/**
	 * 类似Shiro的过滤链定义，用于初始化默认的过滤规则
	 */
	private Map<String /* pattern */, String /* Chain name */> filterChainDefinitionMap = new LinkedHashMap<String, String>();
	@NestedConfigurationProperty
	private SecurityEntryPointProperties entryPoint = new SecurityEntryPointProperties();
	
	public Map<String, String> getFilterChainDefinitionMap() {
		return filterChainDefinitionMap;
	}

	public void setFilterChainDefinitionMap(Map<String, String> filterChainDefinitionMap) {
		this.filterChainDefinitionMap = filterChainDefinitionMap;
	}

	public SecurityEntryPointProperties getEntryPoint() {
		return entryPoint;
	}

	public void setEntryPoint(SecurityEntryPointProperties entryPoint) {
		this.entryPoint = entryPoint;
	}

}
