package org.springframework.security.boot.biz.authentication;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * Post认证请求成功后的处理实现
 * 
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class PostRequestAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private List<AuthenticationListener> authenticationListeners;
	private List<MatchedAuthenticationSuccessHandler> successHandlers;
	private boolean stateless = false;
	
	public PostRequestAuthenticationSuccessHandler(List<MatchedAuthenticationSuccessHandler> successHandlers) {
		this.setSuccessHandlers(successHandlers);
	}

	public PostRequestAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setSuccessHandlers(successHandlers);
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		// 调用事件监听器
		if (getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0) {
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onSuccess(request, response, authentication);
			}
		}

		/*
		 * if Rest request return json else rediect to specific page
		 */
		if ( isStateless() || WebUtils.isPostRequest(request)) {

			if (CollectionUtils.isEmpty(successHandlers)) {
				
				this.writeJSONString(request, response, authentication);
				clearAuthenticationAttributes(request);
				
			} else {

				boolean isMatched = false;
				for (MatchedAuthenticationSuccessHandler successHandler : successHandlers) {

					if (successHandler != null && successHandler.supports(authentication)) {
						successHandler.onAuthenticationSuccess(request, response, authentication);
						isMatched = true;
						break;
					}

				}
				if (!isMatched) {
					this.writeJSONString(request, response, authentication);
				}

				clearAuthenticationAttributes(request);

			}

		} else {
			super.onAuthenticationSuccess(request, response, authentication);
		}

	}

	protected void writeJSONString(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);

		JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHC_SUCCESS.getCode(),
				messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey())));

	}

	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

	public MessageSourceAccessor getMessages() {
		return messages;
	}

	public List<MatchedAuthenticationSuccessHandler> getSuccessHandlers() {
		return successHandlers;
	}

	public void setMessages(MessageSourceAccessor messages) {
		this.messages = messages;
	}

	public void setSuccessHandlers(List<MatchedAuthenticationSuccessHandler> successHandlers) {
		this.successHandlers = successHandlers;
	}

	public boolean isStateless() {
		return stateless;
	}

	public void setStateless(boolean stateless) {
		this.stateless = stateless;
	}

}
