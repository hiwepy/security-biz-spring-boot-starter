package org.springframework.security.boot.biz.exception;

/**
 * Enumeration of response code.
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public enum AuthResponseCode {

	/**
	 * Authentication success
	 */
	SC_AUTHC_SUCCESS("200", AuthConstants.RT_SUCCESS,  "spring.security.authc.success"),
	/**
	 * Authentication Error
	 */
	SC_AUTHC_ERROR("500", AuthConstants.RT_ERROR, "spring.security.authc.error"),
	/**
	 * Logout success
	 */
	SC_AUTHC_LOGOUT("10000", AuthConstants.RT_ERROR, "spring.security.authc.logout"),
	/**
	 * Authentication failed
	 */
	SC_AUTHC_FAIL("10001", AuthConstants.RT_ERROR, "spring.security.authc.fail"),
	/**
	 * Authentication method not supported. 
	 */
	SC_AUTHC_METHOD_NOT_ALLOWED("10002", AuthConstants.RT_ERROR, "spring.security.authc.method-not-supported"),
	/**
	 * The number of login errors exceeds the maximum retry limit and a verification code is required
	 */
	SC_AUTHC_OVER_RETRY_REMIND("10003", AuthConstants.RT_ERROR, "spring.security.authc.over-retry-remind"),
	/**
	 * Captcha failed to send
	 */
	SC_AUTHC_CAPTCHA_SEND_FAIL("10004", AuthConstants.RT_ERROR, "spring.security.authc.captcha.send-fail"),    
	/**
	 * Captcha not provided
	 */
	SC_AUTHC_CAPTCHA_REQUIRED("10005", AuthConstants.RT_ERROR, "spring.security.authc.captcha.required"),
	/**
	 * Captcha was expired
	 */
	SC_AUTHC_CAPTCHA_EXPIRED("10006", AuthConstants.RT_ERROR, "spring.security.authc.captcha.expired"),
	/**
	 * Captcha was invalid
	 */
	SC_AUTHC_CAPTCHA_INVALID("10007", AuthConstants.RT_ERROR, "spring.security.authc.captcha.invalid"),
	/**
	 * Captcha was incorrect
	 */
	SC_AUTHC_CAPTCHA_INCORRECT("10008", AuthConstants.RT_ERROR, "spring.security.authc.captcha.incorrect"),
	/**
	 * User credentials have expired
	 */
	SC_AUTHC_CREDENTIALS_EXPIRED("10009", AuthConstants.RT_ERROR, "spring.security.authc.credentials.expired"),
	/**
	 * Bad credentials
	 */
	SC_AUTHC_CREDENTIALS_INCORRECT("10010", AuthConstants.RT_ERROR, "spring.security.authc.credentials.incorrect"),
	SC_AUTHC_USER_UNREGISTERED("10011", AuthConstants.RT_ERROR, "spring.security.authc.principal.unregistered"),
	SC_AUTHC_USER_REGISTERED("10012", AuthConstants.RT_ERROR, "spring.security.authc.principal.registered"),
	SC_AUTHC_USER_NOT_FOUND("10013", AuthConstants.RT_ERROR, "spring.security.authc.principal.not-found"),
	SC_AUTHC_USER_DISABLED("10014", AuthConstants.RT_ERROR, "spring.security.authc.principal.disabled"),
	SC_AUTHC_USER_EXPIRED("10015", AuthConstants.RT_ERROR, "spring.security.authc.principal.expired"),
	SC_AUTHC_USER_LOCKED("10016", AuthConstants.RT_ERROR, "spring.security.authc.principal.locked"),
	SC_AUTHC_USER_NO_ROLE("10017", AuthConstants.RT_ERROR, "spring.security.authc.principal.no-role"),
	SC_AUTHC_BOUND_NOT_FOUND("10018", AuthConstants.RT_ERROR, "spring.security.authc.bound.not-found"),
	SC_AUTHC_BOUND_INCORRECT("10019", AuthConstants.RT_ERROR, "spring.security.authc.bound.incorrect"),
	
	SC_AUTHZ_SUCCESS("0", AuthConstants.RT_ERROR, "spring.security.authz.success"),
	SC_AUTHZ_FAIL("10021", AuthConstants.RT_ERROR, "spring.security.authz.fail"),
	SC_AUTHZ_CODE_REQUIRED("10022", AuthConstants.RT_ERROR, "spring.security.authz.code.required"),
	SC_AUTHZ_CODE_EXPIRED("10023", AuthConstants.RT_ERROR, "spring.security.authz.code.expired"),
	SC_AUTHZ_CODE_INVALID("10024", AuthConstants.RT_ERROR, "spring.security.authz.code.invalid"),
	SC_AUTHZ_CODE_INCORRECT("10025", AuthConstants.RT_ERROR, "spring.security.authz.code.incorrect"),
	SC_AUTHZ_DINGTALK_REQUIRED("10026", AuthConstants.RT_ERROR, "spring.security.authz.dingtalk.required"),
	SC_AUTHZ_DINGTALK_EXPIRED("10027", AuthConstants.RT_ERROR, "spring.security.authz.dingtalk.expired"),
	SC_AUTHZ_DINGTALK_INVALID("10028", AuthConstants.RT_ERROR, "spring.security.authz.dingtalk.invalid"),
	SC_AUTHZ_DINGTALK_INCORRECT("10029", AuthConstants.RT_ERROR, "spring.security.authz.dingtalk.incorrect"),
	SC_AUTHZ_TOKEN_ISSUED("10030", AuthConstants.RT_ERROR, "spring.security.authz.token.issued"),
	SC_AUTHZ_TOKEN_REQUIRED("10031", AuthConstants.RT_ERROR, "spring.security.authz.token.required"),
	SC_AUTHZ_TOKEN_EXPIRED("10032", AuthConstants.RT_ERROR, "spring.security.authz.token.expired"),
	SC_AUTHZ_TOKEN_INVALID("10033", AuthConstants.RT_ERROR, "spring.security.authz.token.invalid"),
	SC_AUTHZ_TOKEN_INCORRECT("10034", AuthConstants.RT_ERROR, "spring.security.authz.token.incorrect"),
	SC_AUTHZ_THIRD_PARTY_SERVICE("10035", AuthConstants.RT_ERROR, "spring.security.authz.server.error");
	
	private final String code;
	private final String status;
	private final String msgKey;
	
    private AuthResponseCode(String code, String status, String msgKey) {
        this.code = code;
        this.status = status;
        this.msgKey = msgKey;
    }

    public String getCode() {
        return code;
    }
    
    public String getStatus() {
		return status;
	}

	public String getMsgKey() {
        return msgKey;
    }
}
