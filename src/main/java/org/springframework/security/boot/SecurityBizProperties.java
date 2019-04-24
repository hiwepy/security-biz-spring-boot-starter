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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityAnonymousProperties;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityCaptchaProperties;
import org.springframework.security.boot.biz.property.SecurityCorsProperties;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecurityRedirectProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;

@ConfigurationProperties(SecurityBizProperties.PREFIX)
public class SecurityBizProperties {

	public static final String PREFIX = "spring.security";
	
	@NestedConfigurationProperty
	private SecurityAuthcProperties authc = new SecurityAuthcProperties();
	@NestedConfigurationProperty
	private SecurityAnonymousProperties anonymous = new SecurityAnonymousProperties();
	@NestedConfigurationProperty
	private SecurityCorsProperties cors = new SecurityCorsProperties();
	@NestedConfigurationProperty
	private SecurityCsrfProperties csrf = new SecurityCsrfProperties();
	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();
	@NestedConfigurationProperty
	private SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();
	@NestedConfigurationProperty
	private SecurityCaptchaProperties captcha = new SecurityCaptchaProperties();
	
	public SecurityAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityAuthcProperties authc) {
		this.authc = authc;
	}

	public SecurityAnonymousProperties getAnonymous() {
		return anonymous;
	}

	public void setAnonymous(SecurityAnonymousProperties anonymous) {
		this.anonymous = anonymous;
	}

	public SecurityCorsProperties getCors() {
		return cors;
	}

	public void setCors(SecurityCorsProperties cors) {
		this.cors = cors;
	}

	public SecurityCsrfProperties getCsrf() {
		return csrf;
	}

	public void setCsrf(SecurityCsrfProperties csrf) {
		this.csrf = csrf;
	}

	public SecurityLogoutProperties getLogout() {
		return logout;
	}

	public void setLogout(SecurityLogoutProperties logout) {
		this.logout = logout;
	}

	public SecurityRedirectProperties getRedirect() {
		return redirect;
	}

	public void setRedirect(SecurityRedirectProperties redirect) {
		this.redirect = redirect;
	}

	public SecuritySessionMgtProperties getSessionMgt() {
		return sessionMgt;
	}

	public void setSessionMgt(SecuritySessionMgtProperties sessionMgt) {
		this.sessionMgt = sessionMgt;
	}

	public SecurityCaptchaProperties getCaptcha() {
		return captcha;
	}

	public void setCaptcha(SecurityCaptchaProperties captcha) {
		this.captcha = captcha;
	}

}
