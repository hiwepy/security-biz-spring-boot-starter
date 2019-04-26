package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class AuthTokenIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthTokenIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthTokenIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthTokenIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthTokenIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
