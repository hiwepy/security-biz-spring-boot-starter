package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class AuthenticationTokenInvalidException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationTokenInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationTokenInvalidException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthenticationTokenInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationTokenInvalidException(String msg, Throwable t) {
		super(msg, t);
	}
}
