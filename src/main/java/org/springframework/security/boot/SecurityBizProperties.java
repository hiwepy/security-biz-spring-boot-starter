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

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 
 * Security 业务参数配置
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@ConfigurationProperties(SecurityBizProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityBizProperties {

	public static final String PREFIX = "spring.security";
	
	/**
	 * 类似Shiro的过滤链定义，用于初始化默认的过滤规则 Map<pattern, Chain name>
	 */
	private Map<String, String > filterChainDefinitionMap = new LinkedHashMap<>(16);
	/** 
     * Whether stateless session
     */
	private boolean stateless = false;

	@NestedConfigurationProperty
	private SecurityHeadersProperties headers = new SecurityHeadersProperties();

	@NestedConfigurationProperty
	private SecurityHeaderCorsProperties cors = new SecurityHeaderCorsProperties();

	@NestedConfigurationProperty
	private SecurityHeaderCsrfProperties csrf = new SecurityHeaderCsrfProperties();

	@NestedConfigurationProperty
	private SecuritySessionMgtProperties session = new SecuritySessionMgtProperties();

	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();

	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();

	@NestedConfigurationProperty
	private SecurityFailureRetryProperties retry = new SecurityFailureRetryProperties();

	@NestedConfigurationProperty
	private SecurityEntryPointProperties entryPoint = new SecurityEntryPointProperties();

}
