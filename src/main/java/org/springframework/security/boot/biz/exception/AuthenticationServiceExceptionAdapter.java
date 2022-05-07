package org.springframework.security.boot.biz.exception;

import org.springframework.security.authentication.AuthenticationServiceException;

/**
 *  认证服务端异常
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public abstract class AuthenticationServiceExceptionAdapter extends AuthenticationServiceException {

	private final int code;
	private final String msgKey;
	
	public AuthenticationServiceExceptionAdapter(AuthResponseCode code, String msg) {
		super(msg);
		this.code = code.getCode();
		this.msgKey = code.getMsgKey();
	}

	public AuthenticationServiceExceptionAdapter(AuthResponseCode code, String msg, Throwable t) {
		super(msg, t);
		this.code = code.getCode();
		this.msgKey = code.getMsgKey();
	}

	public AuthenticationServiceExceptionAdapter(int code, String msg, Throwable t) {
		super(msg, t);
		this.code = code;
		this.msgKey = null;
	}

	public AuthenticationServiceExceptionAdapter(int code, String msgKey, String msg, Throwable t) {
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
