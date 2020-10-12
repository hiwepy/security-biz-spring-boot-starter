package org.springframework.security.boot.utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

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
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;
import org.springframework.security.boot.biz.exception.AuthenticationServiceExceptionAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.alibaba.fastjson.JSONObject;

public class SecurityResponseUtils {

	protected static Logger logger = LoggerFactory.getLogger(SecurityResponseUtils.class);
	protected static MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	public static void handleSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		logger.debug("Locale : {}" );
		
		// 1、设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		
		// 2、国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey());
		
		// 3、输出JSON格式数据
		JSONObject.writeJSONString(response.getWriter(), AuthResponse.success(message));
		
	}
	
	public static void handleException(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		
		logger.debug("Locale : {}" , LocaleContextHolder.getLocale());
		
		// 1、设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		
		// 2、国际化后的异常信息
		String message = null;
		AuthResponse<String> authResponse = null;
		// 认证异常扩展
		if (e instanceof AuthenticationExceptionAdapter) {
			
			AuthenticationExceptionAdapter ex = (AuthenticationExceptionAdapter)e;
			message = messages.getMessage(ex.getCode().getMsgKey(), ex.getMessage());
			authResponse = AuthResponse.of(ex.getCode().getCode(), message);
			
		} 
		// 服务端认证异常扩展
		else if (e instanceof AuthenticationServiceExceptionAdapter) {
			AuthenticationServiceExceptionAdapter ex = (AuthenticationServiceExceptionAdapter)e;
			message = messages.getMessage(ex.getAuthCode().getMsgKey(), ex.getMessage());
			authResponse = AuthResponse.of(ex.getAuthCode().getCode(), message);
		} 
		// 默认异常
		else if (e instanceof UsernameNotFoundException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getCode(), message);
		} else if (e instanceof BadCredentialsException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(), message);
		}  else if (e instanceof DisabledException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_DISABLED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_DISABLED.getCode(), message);
		}  else if (e instanceof LockedException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_LOCKED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_LOCKED.getCode(), message);
		}  else if (e instanceof AccountExpiredException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getCode(), message);
		}  else if (e instanceof CredentialsExpiredException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getCode(), message);
		} else {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_FAIL.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_FAIL.getCode(), message);
		}
				
		// 3、输出JSON格式数据
		JSONObject.writeJSONString(response.getWriter(), authResponse);
		
	}
	
}