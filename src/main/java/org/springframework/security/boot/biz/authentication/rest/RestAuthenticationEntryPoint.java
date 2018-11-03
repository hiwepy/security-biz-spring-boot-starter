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
package org.springframework.security.boot.biz.authentication.rest;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.exception.AuthMethodNotSupportedException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;

public class RestAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	private final ObjectMapper mapper;
	public RestAuthenticationEntryPoint(final ObjectMapper mapper, String loginFormUrl) {
		super(loginFormUrl);
		this.mapper = mapper;
	}

	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		/*
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (WebUtils.isPostRequest(request)) {
			
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			
			if (e instanceof BadCredentialsException) {
				mapper.writeValue(response.getWriter(), RestErrorResponse.of("Invalid username or password", HttpStatus.UNAUTHORIZED));
			} else if (e instanceof AuthMethodNotSupportedException) {
			    mapper.writeValue(response.getWriter(), RestErrorResponse.of(e.getMessage(), HttpStatus.UNAUTHORIZED));
			}

			mapper.writeValue(response.getWriter(), RestErrorResponse.of("Authentication failed", HttpStatus.UNAUTHORIZED));
			
		} else {
			super.commence(request, response, e);
		}

	}

}
