package org.springframework.security.boot.biz.authentication;

import java.io.IOException;
import java.util.List;

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
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;

import com.alibaba.fastjson.JSONObject;

/**
 * Post认证请求失败后的处理实现
 */
public class PostRequestAuthenticationFailureHandler extends ExceptionMappingAuthenticationFailureHandler {

	private List<AuthenticationListener> authenticationListeners;
	
	public PostRequestAuthenticationFailureHandler(String defaultFailureUrl) {
		this.setDefaultFailureUrl(defaultFailureUrl);
	}
	
	public PostRequestAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners, String defaultFailureUrl) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setDefaultFailureUrl(defaultFailureUrl);
	}
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onFailure(request, response, e);
			}
		}
		
		/*
		 * if Rest request return json else rediect to specific page
		 */
		if (WebUtils.isPostRequest(request)) {
			this.writeJSONString(request, response, e);
		} else {
			super.onAuthenticationFailure(request, response, e);
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

	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

}
