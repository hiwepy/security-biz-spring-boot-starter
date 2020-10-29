package org.springframework.security.boot.biz.exception;

/**
 * Enumeration of response code.
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public enum AuthResponseCode {

	/**
	 * Authentication success
	 */
	SC_AUTHC_SUCCESS(ApiCodeValue.SC_SUCCESS, AuthConstants.RT_SUCCESS, "spring.security.authc.success"),

	/**
	 * Authentication failed
	 */
	SC_AUTHC_FAIL(ApiCodeValue.SC_AUTHC_FAIL, AuthConstants.RT_ERROR, "spring.security.authc.fail"),

	/**
	 * Authentication method not supported.
	 */
	SC_AUTHC_METHOD_NOT_ALLOWED(ApiCodeValue.SC_AUTHC_METHOD_NOT_ALLOWED, AuthConstants.RT_ERROR,
			"spring.security.authc.method-not-supported"),
	/**
	 * The number of login errors exceeds the maximum retry limit and a verification
	 * code is required
	 */
	SC_AUTHC_OVER_RETRY_REMIND(ApiCodeValue.SC_AUTHC_OVER_RETRY_REMIND, AuthConstants.RT_ERROR,
			"spring.security.authc.over-retry-remind"),
	/**
	 * Captcha not provided
	 */
	SC_AUTHC_CAPTCHA_REQUIRED(ApiCodeValue.SC_AUTHC_CAPTCHA_REQUIRED, AuthConstants.RT_ERROR,
			"spring.security.authc.captcha.required"),
	/**
	 * Captcha was expired
	 */
	SC_AUTHC_CAPTCHA_EXPIRED(ApiCodeValue.SC_AUTHC_CAPTCHA_EXPIRED, AuthConstants.RT_ERROR,
			"spring.security.authc.captcha.expired"),
	/**
	 * Captcha was incorrect
	 */
	SC_AUTHC_CAPTCHA_INCORRECT(ApiCodeValue.SC_AUTHC_CAPTCHA_INCORRECT, AuthConstants.RT_ERROR,
			"spring.security.authc.captcha.incorrect"),
	
	/**
	 * User account does not exist
	 */
	SC_AUTHC_ACCOUNT_NOT_FOUND(ApiCodeValue.SC_AUTHC_ACCOUNT_NOT_FOUND, AuthConstants.RT_ERROR,
			"spring.security.authc.principal.not-found"),
	/**
	 * User account not enabled
	 */
	SC_AUTHC_ACCOUNT_DISABLED(ApiCodeValue.SC_AUTHC_ACCOUNT_DISABLED, AuthConstants.RT_ERROR,
			"spring.security.authc.principal.disabled"),
	/**
	 * User account has expired
	 */
	SC_AUTHC_ACCOUNT_EXPIRED(ApiCodeValue.SC_AUTHC_ACCOUNT_EXPIRED, AuthConstants.RT_ERROR,
			"spring.security.authc.principal.expired"),
	/**
	 * User account is locked
	 */
	SC_AUTHC_ACCOUNT_LOCKED(ApiCodeValue.SC_AUTHC_ACCOUNT_LOCKED, AuthConstants.RT_ERROR,
			"spring.security.authc.principal.locked"),

	/**
	 * User credentials have expired
	 */
	SC_AUTHC_CREDENTIALS_EXPIRED(ApiCodeValue.SC_AUTHC_CREDENTIALS_EXPIRED, AuthConstants.RT_ERROR,
			"spring.security.authc.credentials.expired"),
	/**
	 * Bad credentials
	 */
	SC_AUTHC_BAD_CREDENTIALS(ApiCodeValue.SC_AUTHC_BAD_CREDENTIALS, AuthConstants.RT_ERROR,
			"spring.security.authc.credentials.incorrect"),
	
	/**
	 * Authorization success
	 */
	SC_AUTHZ_SUCCESS(ApiCodeValue.SC_SUCCESS, AuthConstants.RT_SUCCESS, "spring.security.authz.success"),
	/**
	 * Authorization failed
	 */
	SC_AUTHZ_FAIL(ApiCodeValue.SC_AUTHZ_FAIL, AuthConstants.RT_ERROR, "spring.security.authz.fail"),
	/**
	 * Token issue failed
	 */
	SC_AUTHZ_TOKEN_ISSUED(ApiCodeValue.SC_AUTHZ_TOKEN_ISSUED, AuthConstants.RT_ERROR,
			"spring.security.authz.token.issued"),
	/**
	 * Token not provided
	 */
	SC_AUTHZ_TOKEN_REQUIRED(ApiCodeValue.SC_AUTHZ_TOKEN_REQUIRED, AuthConstants.RT_ERROR,
			"spring.security.authz.token.required"),
	/**
	 * Token was expired
	 */
	SC_AUTHZ_TOKEN_EXPIRED(ApiCodeValue.SC_AUTHZ_TOKEN_EXPIRED, AuthConstants.RT_ERROR,
			"spring.security.authz.token.expired"),
	/**
	 * Token was invalid
	 */
	SC_AUTHZ_TOKEN_INVALID(ApiCodeValue.SC_AUTHZ_TOKEN_INVALID, AuthConstants.RT_ERROR,
			"spring.security.authz.token.invalid"),
	/**
	 * Token was incorrect
	 */
	SC_AUTHZ_TOKEN_INCORRECT(ApiCodeValue.SC_AUTHZ_TOKEN_INCORRECT, AuthConstants.RT_ERROR,
			"spring.security.authz.token.incorrect"),
	/**
	 * Authorization code not provided
	 */
	SC_AUTHZ_CODE_REQUIRED(ApiCodeValue.SC_AUTHZ_CODE_REQUIRED, AuthConstants.RT_ERROR,
			"spring.security.authz.code.required"),
	/**
	 * Authorization code was expired
	 */
	SC_AUTHZ_CODE_EXPIRED(ApiCodeValue.SC_AUTHZ_CODE_EXPIRED, AuthConstants.RT_ERROR,
			"spring.security.authz.code.expired"),
	/**
	 * Authorization code was invalid
	 */
	SC_AUTHZ_CODE_INVALID(ApiCodeValue.SC_AUTHZ_CODE_INVALID, AuthConstants.RT_ERROR,
			"spring.security.authz.code.invalid"),
	/**
	 * Authorization code was incorrect
	 */
	SC_AUTHZ_CODE_INCORRECT(ApiCodeValue.SC_AUTHZ_CODE_INCORRECT, AuthConstants.RT_ERROR,
			"spring.security.authz.code.incorrect"),
	/**
	 * Third-party authorization server exception
	 */
	SC_AUTHZ_THIRD_PARTY_SERVICE(ApiCodeValue.SC_AUTHZ_THIRD_PARTY_SERVICE, AuthConstants.RT_ERROR,
			"spring.security.authz.server.error");

	private final int code;
	private final String status;
	private final String msgKey;

	private AuthResponseCode(int code, String status, String msgKey) {
		this.code = code;
		this.status = status;
		this.msgKey = msgKey;
	}

	public int getCode() {
		return code;
	}

	public String getStatus() {
		return status;
	}

	public String getMsgKey() {
		return msgKey;
	}
}
