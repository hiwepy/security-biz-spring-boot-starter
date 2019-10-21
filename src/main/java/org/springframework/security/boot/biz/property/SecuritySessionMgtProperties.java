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

import javax.servlet.http.HttpServletResponse;

import org.springframework.security.config.http.SessionCreationPolicy;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class SecuritySessionMgtProperties {
	
	private boolean allowSessionCreation = false;
	/** if should allow the JSESSIONID to be rewritten into the URLs*/
	
	/**
	 * If set to true, allows HTTP sessions to be rewritten in the URLs when using
	 * {@link HttpServletResponse#encodeRedirectURL(String)} or
	 * {@link HttpServletResponse#encodeURL(String)}, otherwise disallows HTTP
	 * sessions to be included in the URL. This prevents leaking information to
	 * external domains.
	 *
	 * enableSessionUrlRewriting true if should allow the JSESSIONID to be
	 *                                  rewritten into the URLs, else false
	 *                                  (default)
	 */
	private boolean enableSessionUrlRewriting;
	/**  */
	private String failureUrl = "/error";
	/**
	 * Controls the maximum number of sessions for a user. The default is to allow
	 * any number of users.
	 * 
	 * maximumSessions the maximum number of sessions for a user
	 */
	private Integer maximumSessions = Integer.MAX_VALUE;
	/**
	 * If true, prevents a user from authenticating when the
	 * {@link #maximumSessions(int)} has been reached. Otherwise (default), the user
	 * who authenticates is allowed access and an existing user's session is
	 * expired. The user's who's session is forcibly expired is sent to
	 * {@link #expiredUrl(String)}. The advantage of this approach is if a user
	 * accidentally does not log out, there is no need for an administrator to
	 * intervene or wait till their session expires.
	 */
	private boolean maxSessionsPreventsLogin = false;
	
	private SessionCreationPolicy creationPolicy = SessionCreationPolicy.STATELESS;
	private SessionFixationPolicy fixationPolicy = SessionFixationPolicy.NONE;
	/**
	 * If the {@code sessionAttrName} property is set, the request is stored in
	 * the session using this attribute name. Default is
	 * "SPRING_SECURITY_SAVED_REQUEST".
	 */
	private String sessionAttrName = "SPRING_SECURITY_SAVED_REQUEST";
	
	private boolean useForward = false;
	
}
