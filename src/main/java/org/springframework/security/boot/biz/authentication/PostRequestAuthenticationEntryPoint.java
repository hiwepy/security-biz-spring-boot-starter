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
package org.springframework.security.boot.biz.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.CollectionUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * Post Request Authentication Entry Point
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class PostRequestAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private List<MatchedAuthenticationEntryPoint> entryPoints;
	private boolean stateless = false;
	
	public PostRequestAuthenticationEntryPoint(String loginFormUrl, List<MatchedAuthenticationEntryPoint> entryPoints) {
		super(loginFormUrl);
		this.entryPoints = entryPoints;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		/*
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (isStateless() || WebUtils.isPostRequest(request)) {
			
			if(CollectionUtils.isEmpty(entryPoints)) {
				this.writeJSONString(request, response, e);
			} else {
				
				boolean isMatched = false;
				for (MatchedAuthenticationEntryPoint entryPoint : entryPoints) {
					
					if(entryPoint != null && entryPoint.supports(e)) {
						entryPoint.commence(request, response, e);
						isMatched = true;
						break;
					}
					
				}
				if(!isMatched) {
					this.writeJSONString(request, response, e);
				}
			}
			
		} else {
			super.commence(request, response, e);
		}
	}

	protected void writeJSONString(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException{
		
		logger.debug("Locale : {}" , LocaleContextHolder.getLocale());
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		
		if (e instanceof UsernameNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getMsgKey(), e.getMessage())));
		} else if (e instanceof BadCredentialsException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(), e.getMessage())));
		}  else if (e instanceof DisabledException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_DISABLED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_DISABLED.getMsgKey(), e.getMessage())));
		}  else if (e instanceof LockedException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_LOCKED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_LOCKED.getMsgKey(), e.getMessage())));	
		}  else if (e instanceof AccountExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getMsgKey(), e.getMessage())));	
		}  else if (e instanceof CredentialsExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getMsgKey(), e.getMessage())));	
		} else {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_FAIL.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_FAIL.getMsgKey())));
		}
		
	}

	public MessageSourceAccessor getMessages() {
		return messages;
	}

	public List<MatchedAuthenticationEntryPoint> getEntryPoints() {
		return entryPoints;
	}

	public boolean isStateless() {
		return stateless;
	}

	public void setMessages(MessageSourceAccessor messages) {
		this.messages = messages;
	}

	public void setEntryPoints(List<MatchedAuthenticationEntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}

	public void setStateless(boolean stateless) {
		this.stateless = stateless;
	}
	
}