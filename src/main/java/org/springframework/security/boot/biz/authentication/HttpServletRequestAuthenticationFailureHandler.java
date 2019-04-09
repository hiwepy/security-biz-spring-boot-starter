package org.springframework.security.boot.biz.authentication;

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
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Post认证请求失败后的处理实现
 */
public class HttpServletRequestAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	private final ObjectMapper mapper;

	public HttpServletRequestAuthenticationFailureHandler(final ObjectMapper mapper) {
		this.mapper = mapper;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		/*
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (WebUtils.isPostRequest(request)) {

			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

			if (e instanceof BadCredentialsException) {
				mapper.writeValue(response.getWriter(), HttpServletRequestErrorResponse.of("Invalid username or password", HttpStatus.UNAUTHORIZED));
			} else if (e instanceof AuthMethodNotSupportedException) {
				mapper.writeValue(response.getWriter(), HttpServletRequestErrorResponse.of(e.getMessage(), HttpStatus.UNAUTHORIZED));
			} else {
				mapper.writeValue(response.getWriter(), HttpServletRequestErrorResponse.of("Authentication failed", HttpStatus.UNAUTHORIZED));
			}
		} else {
			super.onAuthenticationFailure(request, response, e);
		}

	}

}
