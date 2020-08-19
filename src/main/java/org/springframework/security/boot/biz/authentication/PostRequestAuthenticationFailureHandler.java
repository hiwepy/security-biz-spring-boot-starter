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
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.util.CollectionUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * Post Request Authentication Failure Handler
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class PostRequestAuthenticationFailureHandler extends ExceptionMappingAuthenticationFailureHandler {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private List<AuthenticationListener> authenticationListeners;
	private List<MatchedAuthenticationFailureHandler> failureHandlers;
	private boolean stateless = false;
	
	public PostRequestAuthenticationFailureHandler(List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.setFailureHandlers(failureHandlers);
	}

	public PostRequestAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setFailureHandlers(failureHandlers);
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		// 调用事件监听器
		if (getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0) {
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onFailure(request, response, e);
			}
		}

		/*
		 * if Rest request return json else rediect to specific page
		 */
		if (isStateless() || WebUtils.isPostRequest(request)) {
			
			if(CollectionUtils.isEmpty(failureHandlers)) {
				this.writeJSONString(request, response, e);
			} else {
				
				boolean isMatched = false;
				for (MatchedAuthenticationFailureHandler failureHandler : failureHandlers) {
					
					if(failureHandler != null && failureHandler.supports(e)) {
						failureHandler.onAuthenticationFailure(request, response, e);
						isMatched = true;
						break;
					}
					
				}
				if(!isMatched) {
					this.writeJSONString(request, response, e);
				}
			}
			
		} else {
			super.onAuthenticationFailure(request, response, e);
		}

	}

	protected void writeJSONString(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {

		logger.debug("Locale : {}" , LocaleContextHolder.getLocale());
		
		// 1、设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		
		// 2、国际化后的异常信息
		String message = null;
		AuthResponse<String> authResponse = null;
		if (e instanceof UsernameNotFoundException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getMsgKey(), e.getMessage(), LocaleContextHolder.getLocale());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getCode(), message);
		} else if (e instanceof BadCredentialsException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(), e.getMessage(), LocaleContextHolder.getLocale());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(), message);
		}  else if (e instanceof DisabledException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_DISABLED.getMsgKey(), e.getMessage(), LocaleContextHolder.getLocale());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_DISABLED.getCode(), message);
		}  else if (e instanceof LockedException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_LOCKED.getMsgKey(), e.getMessage(), LocaleContextHolder.getLocale());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_LOCKED.getCode(), message);
		}  else if (e instanceof AccountExpiredException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getMsgKey(), e.getMessage(), LocaleContextHolder.getLocale());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getCode(), message);
		}  else if (e instanceof CredentialsExpiredException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getMsgKey(), e.getMessage(), LocaleContextHolder.getLocale());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getCode(), message);
		} else {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_FAIL.getMsgKey(), e.getMessage(), LocaleContextHolder.getLocale());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_FAIL.getCode(), message);
		}
		
		// 3、输出JSON格式数据
		JSONObject.writeJSONString(response.getWriter(), authResponse);
		
		
	}
	
	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

	public List<MatchedAuthenticationFailureHandler> getFailureHandlers() {
		return failureHandlers;
	}

	public void setFailureHandlers(List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.failureHandlers = failureHandlers;
	}

	public void setMessages(MessageSourceAccessor messages) {
		this.messages = messages;
	}
	
	public MessageSourceAccessor getMessages() {
		return messages;
	}

	public boolean isStateless() {
		return stateless;
	}

	public void setStateless(boolean stateless) {
		this.stateless = stateless;
	}

}