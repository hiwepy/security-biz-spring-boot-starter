package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

public class AuthTokenExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthTokenExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthTokenExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthTokenExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthTokenExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
