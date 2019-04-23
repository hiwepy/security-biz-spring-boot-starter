package org.springframework.security.boot.biz.authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import com.alibaba.fastjson.JSONObject;

/**
 * Post认证请求成功后的处理实现
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class PostRequestAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
	
	private List<AuthenticationListener> authenticationListeners;
	
	public PostRequestAuthenticationSuccessHandler(String defaultTargetUrl) {
		this.setDefaultTargetUrl(defaultTargetUrl);
	}
	
	public PostRequestAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners, String defaultTargetUrl) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setDefaultTargetUrl(defaultTargetUrl);
	}
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onSuccess(request, response, authentication);
			}
		}
		
		/*
		 * 判断是否Post请求
		 */
		if (WebUtils.isPostRequest(request)) {
			
			Map<String, String> retMap = new HashMap<String, String>();
			retMap.put("status", "1");
			retMap.put("successUrl", getDefaultTargetUrl());

			response.setStatus(HttpStatus.OK.value());
			response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
			
			JSONObject.writeJSONString(response.getWriter(), retMap);

			clearAuthenticationAttributes(request);
		} else {
			super.onAuthenticationSuccess(request, response, authentication);
		}

	}

	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

}
