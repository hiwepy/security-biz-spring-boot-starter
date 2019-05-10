package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class AuthenticationTokenExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthTokenExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationTokenExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthTokenExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationTokenExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
