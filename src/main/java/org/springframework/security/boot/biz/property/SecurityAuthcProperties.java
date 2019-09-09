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
package org.springframework.security.boot.biz.property;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;

public class SecurityAuthcProperties {

	/** 登录地址：会话不存在时访问的地址 */
	private String loginUrl = "/login";
	/** 重定向地址：会话注销后的重定向地址 */
	private String redirectUrl = "/";
	/** 系统主页：登录成功后跳转路径 */
	private String successUrl = "/index";;
	/** 未授权页面：无权限时的跳转路径 */
	private String unauthorizedUrl = "/error";
	/** 异常页面：认证失败时的跳转路径 */
	private String failureUrl = "/error";

	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = false;
	/** the username parameter name. Defaults to "username". */
	private String usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
	/** the password parameter name. Defaults to "password". */
	private String passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
	private String targetUrlParameter = "target";
	private boolean alwaysUseDefaultTargetUrl = false;
	private boolean useReferer = false;
	private boolean postOnly = true;
	private boolean forceHttps = false;
	private boolean useForward = false;

    private String retryTimesKeyParameter = AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME;
    private String retryTimesKeyAttribute = PostRequestAuthenticationProcessingFilter.DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
	/** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	
	public String getLoginUrl() {
		return loginUrl;
	}

	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
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

	public boolean isContinueChainBeforeSuccessfulAuthentication() {
		return continueChainBeforeSuccessfulAuthentication;
	}

	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	public void setContinueChainBeforeSuccessfulAuthentication(
			boolean continueChainBeforeSuccessfulAuthentication) {
		this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
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
	
	/**
	 * If this property is set, the current request will be checked for this a parameter
	 * with this name and the value used as the target URL if present.
	 *
	 * @param targetUrlParameter the name of the parameter containing the encoded target
	 * URL. Defaults to null.
	 */
	public void setTargetUrlParameter(String targetUrlParameter) {
		if (targetUrlParameter != null) {
			Assert.hasText(targetUrlParameter, "targetUrlParameter cannot be empty");
		}
		this.targetUrlParameter = targetUrlParameter;
	}

	public String getTargetUrlParameter() {
		return targetUrlParameter;
	}
	
	public boolean isAlwaysUseDefaultTargetUrl() {
		return alwaysUseDefaultTargetUrl;
	}

	public void setAlwaysUseDefaultTargetUrl(boolean alwaysUseDefaultTargetUrl) {
		this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
	}

	public boolean isUseReferer() {
		return useReferer;
	}

	public void setUseReferer(boolean useReferer) {
		this.useReferer = useReferer;
	}

	public boolean isPostOnly() {
		return postOnly;
	}

	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
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
	
	public String getRetryTimesKeyParameter() {
		return retryTimesKeyParameter;
	}

	public void setRetryTimesKeyParameter(String retryTimesKeyParameter) {
		this.retryTimesKeyParameter = retryTimesKeyParameter;
	}
	
	public String getRetryTimesKeyAttribute() {
		return retryTimesKeyAttribute;
	}

	public void setRetryTimesKeyAttribute(String retryTimesKeyAttribute) {
		this.retryTimesKeyAttribute = retryTimesKeyAttribute;
	}

	public int getRetryTimesWhenAccessDenied() {
		return retryTimesWhenAccessDenied;
	}

	public void setRetryTimesWhenAccessDenied(int retryTimesWhenAccessDenied) {
		this.retryTimesWhenAccessDenied = retryTimesWhenAccessDenied;
	}

}
