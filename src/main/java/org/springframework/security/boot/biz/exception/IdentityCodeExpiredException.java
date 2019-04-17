package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

public class IdentityCodeExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public IdentityCodeExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public IdentityCodeExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
