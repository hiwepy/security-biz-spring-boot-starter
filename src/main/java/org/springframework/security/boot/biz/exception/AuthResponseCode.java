package org.springframework.security.boot.biz.exception;

/**
 * Enumeration of response code.
 */
public enum AuthResponseCode {
	
	SC_AUTHC_SUCCESS("0", "spring.security.authc.success"),
	SC_AUTHC_FAIL("10001", "spring.security.authc.fail"),
	SC_AUTHC_METHOD_NOT_ALLOWED("10002", "spring.security.authc.method-not-supported"),
	SC_AUTHC_OVER_RETRY_REMIND("10003", "spring.security.authc.over-retry-remind"),
	SC_AUTHC_CAPTCHA_SEND_FAIL("10004", "spring.security.authc.captcha.send-fail"),     
	SC_AUTHC_CAPTCHA_REQUIRED("10005", "spring.security.authc.captcha.required"),
	SC_AUTHC_CAPTCHA_EXPIRED("10006", "spring.security.authc.captcha.expired"),
	SC_AUTHC_CAPTCHA_INVALID("10007", "spring.security.authc.captcha.invalid"),
	SC_AUTHC_CAPTCHA_INCORRECT("10008", "spring.security.authc.captcha.incorrect"),
	SC_AUTHC_CREDENTIALS_EXPIRED("10009", "spring.security.authc.credentials.expired"),
	SC_AUTHC_CREDENTIALS_INCORRECT("10010", "spring.security.authc.credentials.incorrect"),
	SC_AUTHC_USER_UNREGISTERED("10011", "spring.security.authc.principal.unregistered"),
	SC_AUTHC_USER_REGISTERED("10012", "spring.security.authc.principal.registered"),
	SC_AUTHC_USER_NOT_FOUND("10013", "spring.security.authc.principal.not-found"),
	SC_AUTHC_USER_DISABLED("10014", "spring.security.authc.principal.disabled"),
	SC_AUTHC_USER_EXPIRED("10015", "spring.security.authc.principal.expired"),
	SC_AUTHC_USER_LOCKED("10016", "spring.security.authc.principal.locked"),
	SC_AUTHC_USER_NO_ROLE("10017", "spring.security.authc.principal.no-role"),
	
	SC_AUTHZ_SUCCESS("0", "spring.security.authz.success"),
	SC_AUTHZ_FAIL("10021", "spring.security.authz.fail"),
	SC_AUTHZ_TOKEN_REQUIRED("10022", "spring.security.authz.token.required"),
	SC_AUTHZ_TOKEN_EXPIRED("10023", "spring.security.authz.token.expired"),
	SC_AUTHZ_TOKEN_INVALID("10024", "spring.security.authz.token.invalid"),
	SC_AUTHZ_TOKEN_INCORRECT("10025", "spring.security.authz.token.incorrect"),
	
	SC_AUTHZ_THIRD_PARTY_EXPIRED("10026", "spring.security.authz.code.expired"),
	SC_AUTHZ_THIRD_PARTY_SERVICE("10027", "spring.security.authz.server.error"),
	SC_AUTHZ_THIRD_PARTY_INCORRECT("10028", "spring.security.authz.code.incorrect");
	
	private final String code;
	private final String msgKey;
	
    private AuthResponseCode(String code, String msgKey) {
        this.code = code;
        this.msgKey = msgKey;
    }

    public String getCode() {
        return code;
    }
    
    public String getMsgKey() {
        return msgKey;
    }
}
