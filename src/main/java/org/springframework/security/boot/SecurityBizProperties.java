/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
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

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityAnonymousProperties;
import org.springframework.security.boot.biz.property.SecurityCorsProperties;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;

@ConfigurationProperties(SecurityBizProperties.PREFIX)
public class SecurityBizProperties {

	public static final String PREFIX = "spring.security";
	
	public static final String DEFAULT_SESSION_CAPTCHA_KEY = "KAPTCHA_SESSION_KEY";

	public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
	public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
	
	/* ================================== Security Basic ================================= */
	
	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = false;
	
	/**
     * 是否校验验证码
     */
	protected boolean validateCaptcha = false;
	/**
	 * Enable Security.
	 */
	private boolean enabled = false;

	/** The Ant Pattern to match on (i.e. "/admin/**") */
	private String antPattern = "/**";
	/** The Spring MVC Pattern to match on (i.e. "/admin/**") */
	private String mvcPattern;
	/** The Regular Expression to match on (i.e. "/admin/.+") */
	private String regexPattern;
	
	/** 登录地址：会话不存在时访问的地址 */
	private String loginUrl;
	private String loginUrlPatterns;
	private boolean loginAjax = false;
	private boolean allowSessionCreation = true;
	/**  the parameter name. Defaults to "username". */
	private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
	/** the parameter name. Defaults to "password". */
	private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
	private boolean postOnly = true;
	
	/** 注销地址：会话注销后的重定向地址 */
	private String logoutUrl;
	private String logoutUrlPatterns;
	private boolean forceHttps = false;
	private boolean useForward = false;
	
	/** 重定向地址：会话注销后的重定向地址 */
    private String redirectUrl;
	/** 系统主页：登录成功后跳转路径 */
    private String successUrl;
    /** 未授权页面：无权限时的跳转路径 */
    private String unauthorizedUrl;
    /** 异常页面：认证失败时的跳转路径 */
    private String failureUrl;
    
    private boolean multipleSession = false;
    private Integer maximumSessions;
	private String expiredUrl;
	private boolean maxSessionsPreventsLogin;
    
    /** Referrer-Policy Default value is: Referrer-Policy: no-referrer */
    private ReferrerPolicy referrerPolicy = ReferrerPolicy.NO_REFERRER;
    private XFrameOptionsMode frameOptions = XFrameOptionsMode.ALLOW_FROM;
    
    @NestedConfigurationProperty
	private SecurityAnonymousProperties anonymous = new SecurityAnonymousProperties();
    @NestedConfigurationProperty
   	private SecurityCorsProperties cors = new SecurityCorsProperties();
    @NestedConfigurationProperty
	private SecurityCsrfProperties csrf = new SecurityCsrfProperties();
    @NestedConfigurationProperty
   	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
    
	public String getAntPattern() {
		return antPattern;
	}

	public void setAntPattern(String antPattern) {
		this.antPattern = antPattern;
	}

	public String getMvcPattern() {
		return mvcPattern;
	}

	public void setMvcPattern(String mvcPattern) {
		this.mvcPattern = mvcPattern;
	}

	public String getRegexPattern() {
		return regexPattern;
	}

	public void setRegexPattern(String regexPattern) {
		this.regexPattern = regexPattern;
	}

	public boolean isLoginAjax() {
		return loginAjax;
	}

	public void setLoginAjax(boolean loginAjax) {
		this.loginAjax = loginAjax;
	}

	public boolean isForceHttps() {
		return forceHttps;
	}

	public void setForceHttps(boolean forceHttps) {
		this.forceHttps = forceHttps;
	}

	public boolean isUseForward() {
		return useForward;
	}

	public void setUseForward(boolean useForward) {
		this.useForward = useForward;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public boolean isValidateCaptcha() {
		return validateCaptcha;
	}

	public void setValidateCaptcha(boolean validateCaptcha) {
		this.validateCaptcha = validateCaptcha;
	}

	public String getLoginUrl() {
		return loginUrl;
	}

	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	public String getLoginUrlPatterns() {
		return loginUrlPatterns;
	}

	public void setLoginUrlPatterns(String loginUrlPatterns) {
		this.loginUrlPatterns = loginUrlPatterns;
	}

	public String getLogoutUrl() {
		return logoutUrl;
	}

	public void setLogoutUrl(String logoutUrl) {
		this.logoutUrl = logoutUrl;
	}

	public String getLogoutUrlPatterns() {
		return logoutUrlPatterns;
	}

	public void setLogoutUrlPatterns(String logoutUrlPatterns) {
		this.logoutUrlPatterns = logoutUrlPatterns;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

	public String getSuccessUrl() {
		return successUrl;
	}

	public void setSuccessUrl(String successUrl) {
		this.successUrl = successUrl;
	}

	public String getUnauthorizedUrl() {
		return unauthorizedUrl;
	}

	public void setUnauthorizedUrl(String unauthorizedUrl) {
		this.unauthorizedUrl = unauthorizedUrl;
	}
	
	public String getFailureUrl() {
		return failureUrl;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	public ReferrerPolicy getReferrerPolicy() {
		return referrerPolicy;
	}

	public void setReferrerPolicy(ReferrerPolicy referrerPolicy) {
		this.referrerPolicy = referrerPolicy;
	}

	public XFrameOptionsMode getFrameOptions() {
		return frameOptions;
	}

	public void setFrameOptions(XFrameOptionsMode frameOptions) {
		this.frameOptions = frameOptions;
	}

	public boolean isAllowSessionCreation() {
		return allowSessionCreation;
	}

	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

	public String getUsernameParameter() {
		return usernameParameter;
	}

	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}

	public String getPasswordParameter() {
		return passwordParameter;
	}

	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

	public boolean isPostOnly() {
		return postOnly;
	}

	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

	public Integer getMaximumSessions() {
		return maximumSessions;
	}

	public boolean isMultipleSession() {
		return multipleSession;
	}

	public void setMultipleSession(boolean multipleSession) {
		this.multipleSession = multipleSession;
	}

	public void setMaximumSessions(Integer maximumSessions) {
		this.maximumSessions = maximumSessions;
	}

	public String getExpiredUrl() {
		return expiredUrl;
	}

	public void setExpiredUrl(String expiredUrl) {
		this.expiredUrl = expiredUrl;
	}

	public boolean isMaxSessionsPreventsLogin() {
		return maxSessionsPreventsLogin;
	}

	public void setMaxSessionsPreventsLogin(boolean maxSessionsPreventsLogin) {
		this.maxSessionsPreventsLogin = maxSessionsPreventsLogin;
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

	public boolean isContinueChainBeforeSuccessfulAuthentication() {
		return continueChainBeforeSuccessfulAuthentication;
	}

	public void setContinueChainBeforeSuccessfulAuthentication(boolean continueChainBeforeSuccessfulAuthentication) {
		this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
	}

	
	
}

