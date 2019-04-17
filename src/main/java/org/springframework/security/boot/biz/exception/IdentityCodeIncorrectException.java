package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

public class IdentityCodeIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public IdentityCodeIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public IdentityCodeIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
