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
package org.springframework.security.boot.biz.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.exception.AuthMethodNotSupportedException;
import org.springframework.security.boot.biz.exception.AuthTokenExpiredException;
import org.springframework.security.boot.biz.exception.AuthTokenIncorrectException;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaIncorrectException;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaNotFoundException;
import org.springframework.security.boot.biz.exception.ErrorCode;
import org.springframework.security.boot.biz.exception.ErrorResponse;
import org.springframework.security.boot.biz.exception.IdentityCodeExpiredException;
import org.springframework.security.boot.biz.exception.IdentityCodeIncorrectException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.alibaba.fastjson.JSONObject;

public class PostRequestAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	public PostRequestAuthenticationEntryPoint(String loginFormUrl) {
		super(loginFormUrl);
	}

	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		/*
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (WebUtils.isPostRequest(request)) {
			this.writeJSONString(request, response, e);
		} else {
			super.commence(request, response, e);
		}

	}

	protected void writeJSONString(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException{
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		if (e instanceof UsernameNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		}  else if (e instanceof BadCredentialsException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		}  else if (e instanceof AuthenticationCaptchaNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of(e.getMessage(), ErrorCode.CAPTCHA, HttpStatus.UNAUTHORIZED));
		}  else if (e instanceof AuthenticationCaptchaIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of(e.getMessage(), ErrorCode.CAPTCHA, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof IdentityCodeIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Code was incorrect", ErrorCode.IDENTITY, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof IdentityCodeExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Code has expired", ErrorCode.IDENTITY, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof AuthTokenIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Token was incorrect", ErrorCode.TOKEN, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof AuthTokenExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Token has expired", ErrorCode.TOKEN, HttpStatus.UNAUTHORIZED));
		} else if (e instanceof AuthMethodNotSupportedException) {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of(e.getMessage(), ErrorCode.AUTHENTICATION, HttpStatus.METHOD_NOT_ALLOWED));
		} else {
			JSONObject.writeJSONString(response.getWriter(), ErrorResponse.of("Authentication failed", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED));
		}
	}
	
}
