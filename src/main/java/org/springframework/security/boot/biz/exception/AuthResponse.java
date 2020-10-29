package org.springframework.security.boot.biz.exception;

import java.util.HashMap;
import java.util.Map;

/**
 * Auth response for interacting with client.
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public class AuthResponse<T> {

	/**
	 * 成功或异常编码
	 */
	private final int code;
	/**
	 * 旧接口成功、失败或异常辅助判断标记:success、fail、error
	 */
	private final String status;
	/**
	 * 成功或异常消息
	 */
	private final String message;
	/**
	 * 成功或异常数据
	 */
	private T data;

	public AuthResponse(final String message) {
		this.code = AuthResponseCode.SC_AUTHC_SUCCESS.getCode();
		this.status = AuthConstants.RT_SUCCESS;
		this.message = message;
	}

	protected AuthResponse(final AuthResponseCode code) {
		this.code = code.getCode();
		;
		this.status = code.getStatus();
		this.message = null;
	}

	protected AuthResponse(final AuthResponseCode code, final T data) {
		this.code = code.getCode();
		;
		this.status = code.getStatus();
		this.message = null;
		this.data = data;
	}

	protected AuthResponse(final AuthResponseCode code, final String message, final T data) {
		this.code = code.getCode();
		;
		this.status = code.getStatus();
		this.message = message;
		this.data = data;
	}

	protected AuthResponse(final int code, final String message) {
		this(code, AuthConstants.RT_SUCCESS, message);
	}

	protected AuthResponse(final int code, final String status, final String message) {
		this.code = code;
		this.status = status;
		this.message = message;
	}

	protected AuthResponse(final int code, final String message, final T data) {
		this(code, AuthConstants.RT_SUCCESS, message, data);
	}

	protected AuthResponse(final int code, final String status, final String message, final T data) {
		this.code = code;
		this.status = status;
		this.message = message;
		this.data = data;
	}

	// success -----------------------------------------------------------------

	public static <T> AuthResponse<T> success(final String message) {
		return of(AuthResponseCode.SC_AUTHC_SUCCESS, message, null);
	}

	public static <T> AuthResponse<T> success(final T data) {
		return of(AuthResponseCode.SC_AUTHC_SUCCESS, data);
	}

	public static <T> AuthResponse<T> success(final String message, final T data) {
		return of(AuthResponseCode.SC_AUTHC_SUCCESS, message, data);
	}

	public static <T> AuthResponse<T> success(final int code, final String message) {
		return of(code, AuthConstants.RT_SUCCESS, message);
	}

	// fail -----------------------------------------------------------------

	public static <T> AuthResponse<T> fail(final String message) {
		return of(AuthResponseCode.SC_AUTHC_FAIL, message, null);
	}

	public static <T> AuthResponse<T> fail(final T data) {
		return of(AuthResponseCode.SC_AUTHC_FAIL, data);
	}

	public static <T> AuthResponse<T> fail(final int code, final String message) {
		return of(code, AuthConstants.RT_FAIL, message);
	}

	// -----------------------------------------------------------------

	public static <T> AuthResponse<T> of(final AuthResponseCode code) {
		return new AuthResponse<T>(code);
	}

	public static <T> AuthResponse<T> of(final AuthResponseCode code, final T data) {
		return new AuthResponse<T>(code, data);
	}

	public static <T> AuthResponse<T> of(final AuthResponseCode code, final String message, final T data) {
		return new AuthResponse<T>(code, message, data);
	}

	public static <T> AuthResponse<T> of(final String code, final String message) {
		return new AuthResponse<T>(Integer.parseInt(code), message);
	}

	public static <T> AuthResponse<T> of(final int code, final String message) {
		return new AuthResponse<T>(code, message);
	}

	public static <T> AuthResponse<T> of(final String code, final String status, final String message) {
		return of(Integer.parseInt(code), status, message, null);
	}
	
	public static <T> AuthResponse<T> of(final int code, final String status, final String message) {
		return of(code, status, message, null);
	}

	public static <T> AuthResponse<T> of(final int code, final String status, final String message, final T data) {
		return new AuthResponse<T>(code, status, message, data);
	}

	public int getCode() {
		return code;
	}

	public String getStatus() {
		return status;
	}

	public String getmessage() {
		return message;
	}

	public T getData() {
		return data;
	}

	public Map<String, Object> toMap() {
		Map<String, Object> rtMap = new HashMap<String, Object>();
		rtMap.put("code", code);
		rtMap.put("status", status);
		rtMap.put("message", message);
		rtMap.put("data", data);
		return rtMap;
	}

}
