package org.springframework.security.boot.biz.exception;

import org.springframework.security.authentication.AuthenticationServiceException;

/**
 *  认证服务端异常
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public abstract class AuthenticationServiceExceptionAdapter extends AuthenticationServiceException {

	private final AuthResponseCode authCode;
	
	public AuthenticationServiceExceptionAdapter(AuthResponseCode code, String msg) {
		super(msg);
		this.authCode = code;
	}

	public AuthenticationServiceExceptionAdapter(AuthResponseCode code, String msg, Throwable t) {
		super(msg, t);
		this.authCode = code;
	}

	public AuthResponseCode getAuthCode() {
		return authCode;
	}

}
