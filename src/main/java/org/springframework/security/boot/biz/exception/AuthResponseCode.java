package org.springframework.security.boot.biz.exception;

/**
 * Enumeration of response code.
 */
public enum AuthResponseCode {
	
	SC_AUTHC_SUCCESS("0", "spring.security.authc.success"),
	SC_AUTHC_FAIL("1001", "spring.security.authc.fail"),
	SC_AUTHC_METHOD_NOT_ALLOWED("1002", "spring.security.authc.method-not-supported"),
	SC_AUTHC_OVER_RETRY_REMIND("1003", "spring.security.authc.over-retry-remind"),
	SC_AUTHC_CAPTCHA_SEND_FAIL("1004", "spring.security.authc.captcha.send-fail"),     
	SC_AUTHC_CAPTCHA_REQUIRED("1005", "spring.security.authc.captcha.required"),
	SC_AUTHC_CAPTCHA_EXPIRED("1006", "spring.security.authc.captcha.expired"),
	SC_AUTHC_CAPTCHA_INVALID("1007", "spring.security.authc.captcha.invalid"),
	SC_AUTHC_CAPTCHA_INCORRECT("1008", "spring.security.authc.captcha.incorrect"),
	SC_AUTHC_CREDENTIALS_EXPIRED("1009", "spring.security.authc.credentials.expired"),
	SC_AUTHC_CREDENTIALS_INCORRECT("1010", "spring.security.authc.credentials.incorrect"),
	SC_AUTHC_USER_UNREGISTERED("1011", "spring.security.authc.principal.unregistered"),
	SC_AUTHC_USER_REGISTERED("1012", "spring.security.authc.principal.registered"),
	SC_AUTHC_USER_NOT_FOUND("1013", "spring.security.authc.principal.not-found"),
	SC_AUTHC_USER_DISABLED("1014", "spring.security.authc.principal.disabled"),
	SC_AUTHC_USER_EXPIRED("1015", "spring.security.authc.principal.expired"),
	SC_AUTHC_USER_LOCKED("1016", "spring.security.authc.principal.locked"),
	SC_AUTHC_USER_NO_ROLE("1017", "spring.security.authc.principal.no-role"),
	
	SC_AUTHZ_SUCCESS("0", "spring.security.authz.success"),
	SC_AUTHZ_FAIL("1021", "spring.security.authz.fail"),
	SC_AUTHZ_TOKEN_REQUIRED("1022", "spring.security.authz.token.required"),
	SC_AUTHZ_TOKEN_EXPIRED("1023", "spring.security.authz.token.expired"),
	SC_AUTHZ_TOKEN_INVALID("2024", "spring.security.authz.token.invalid"),
	SC_AUTHZ_TOKEN_INCORRECT("2025", "spring.security.authz.token.incorrect"),
	
	SC_AUTHZ_THIRD_PARTY_EXPIRED("1026", "spring.security.authz.code.expired"),
	SC_AUTHZ_THIRD_PARTY_SERVICE("1027", "spring.security.authz.server.error"),
	SC_AUTHZ_THIRD_PARTY_INCORRECT("2028", "spring.security.authz.code.incorrect");
	
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
