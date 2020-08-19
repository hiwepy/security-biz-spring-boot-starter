package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public abstract class AuthenticationExceptionAdapter extends AuthenticationException {

	private final AuthResponseCode code;
	
	public AuthenticationExceptionAdapter(AuthResponseCode code, String msg) {
		super(msg);
		this.code = code;
	}
	
	public AuthenticationExceptionAdapter(AuthResponseCode code, String msg, Throwable t) {
		super(msg, t);
		this.code = code;
	}
	
	public AuthResponseCode getCode() {
		return code;
	}

}
