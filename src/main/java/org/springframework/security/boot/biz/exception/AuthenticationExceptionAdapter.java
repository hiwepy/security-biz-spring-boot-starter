package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public abstract class AuthenticationExceptionAdapter extends AuthenticationException {

	private final int code;
	private final String msgKey;

	public AuthenticationExceptionAdapter(AuthResponseCode code, String msg) {
		super(msg);
		this.code = code.getCode();
		this.msgKey = code.getMsgKey();
	}
	
	public AuthenticationExceptionAdapter(AuthResponseCode code, String msg, Throwable t) {
		super(msg, t);
		this.code = code.getCode();
		this.msgKey = code.getMsgKey();
	}

	public AuthenticationExceptionAdapter(int code, String msg, Throwable t) {
		super(msg, t);
		this.code = code;
		this.msgKey = null;
	}

	public AuthenticationExceptionAdapter(int code, String msgKey, String msg, Throwable t) {
		super(msg, t);
		this.code = code;
		this.msgKey = msgKey;
	}

	public int getCode() {
		return code;
	}

	public String getMsgKey() {
		return msgKey;
	}

}
