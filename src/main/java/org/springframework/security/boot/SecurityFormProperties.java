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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityCaptchaProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Security Form Properties
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@ConfigurationProperties(SecurityFormProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityFormProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.form.authc";
	
	/** Whether Enable Form Authorization. */
	private boolean enabled = false;

	/** 
	 * the username parameter name. Defaults to "username". 
	 */
	private String usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
	/** 
	 * the password parameter name. Defaults to "password". 
	 */
	private String passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
	
	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	
	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	
}
