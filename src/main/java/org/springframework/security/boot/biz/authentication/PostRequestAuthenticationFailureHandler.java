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
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
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
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (WebUtils.isPostRequest(request)) {

			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

			if (e instanceof BadCredentialsException) {
				JSONObject.writeJSONString(response.getWriter(), PostLoginResponse.of("Invalid username or password", HttpStatus.UNAUTHORIZED));
			} else if (e instanceof AuthMethodNotSupportedException) {
				JSONObject.writeJSONString(response.getWriter(), PostLoginResponse.of(e.getMessage(), HttpStatus.UNAUTHORIZED));
			} else {
				JSONObject.writeJSONString(response.getWriter(), PostLoginResponse.of("Authentication failed", HttpStatus.UNAUTHORIZED));
			}
		} else {
			super.onAuthenticationFailure(request, response, e);
		}

	}

	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

}
