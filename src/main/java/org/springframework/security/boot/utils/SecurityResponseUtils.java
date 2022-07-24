package org.springframework.security.boot.utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

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
		JSONObject.writeJSONString(response.getOutputStream(), AuthResponse.success(message));

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
			message = Objects.nonNull(ex.getMsgKey()) ? messages.getMessage(ex.getMsgKey(), ex.getMessage()) : ex.getMessage();
			authResponse = AuthResponse.of(ex.getCode(), message);

		}
		// 服务端认证异常扩展
		else if (e instanceof AuthenticationServiceExceptionAdapter) {
			AuthenticationServiceExceptionAdapter ex = (AuthenticationServiceExceptionAdapter)e;
			message = Objects.nonNull(ex.getMsgKey()) ? messages.getMessage(ex.getMsgKey(), ex.getMessage()) : ex.getMessage();
			authResponse = AuthResponse.of(ex.getCode(), message);
		}
		// 默认异常
		else if (e instanceof UsernameNotFoundException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_ACCOUNT_NOT_FOUND.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_ACCOUNT_NOT_FOUND.getCode(), message);
		} else if (e instanceof BadCredentialsException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_BAD_CREDENTIALS.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_BAD_CREDENTIALS.getCode(), message);
		}  else if (e instanceof DisabledException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_ACCOUNT_DISABLED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_ACCOUNT_DISABLED.getCode(), message);
		}  else if (e instanceof LockedException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_ACCOUNT_LOCKED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_ACCOUNT_LOCKED.getCode(), message);
		}  else if (e instanceof AccountExpiredException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_ACCOUNT_EXPIRED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_ACCOUNT_EXPIRED.getCode(), message);
		}  else if (e instanceof CredentialsExpiredException) {
			message = messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getMsgKey(), e.getMessage());
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getCode(), message);
		} else {
			authResponse = AuthResponse.of(AuthResponseCode.SC_AUTHC_FAIL.getCode(), e.getMessage());
		}

		// 3、输出JSON格式数据
		JSONObject.writeJSONString(response.getOutputStream(), authResponse);

	}

}
