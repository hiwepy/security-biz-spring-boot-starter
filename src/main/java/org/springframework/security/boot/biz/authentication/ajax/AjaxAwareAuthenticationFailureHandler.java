package org.springframework.security.boot.biz.authentication.ajax;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.exception.AuthMethodNotSupportedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.alibaba.fastjson.JSONObject;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 3, 2016
 */
public class AjaxAwareAuthenticationFailureHandler implements AuthenticationFailureHandler {
    
	/** 异常页面：认证失败时的跳转路径 */
    private String failureUrl;
    
    public AjaxAwareAuthenticationFailureHandler(final String failureUrl) {
        this.failureUrl = failureUrl;
    }
    
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		
		Map<String, String> retMap = new HashMap<String, String>();
        retMap.put("status", "0");
        retMap.put("failureUrl", failureUrl);

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		
		if (e instanceof BadCredentialsException) {
			retMap.put("message", "Invalid username or password");
		} else if (e instanceof AuthMethodNotSupportedException) {
			retMap.put("message", e.getMessage());
		} else {
			retMap.put("message", "Authentication failed");
		}
		response.getWriter().write(JSONObject.toJSONString(retMap));
		
	}
}
