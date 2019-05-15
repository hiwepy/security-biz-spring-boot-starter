package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class AuthenticationTokenIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationTokenIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationTokenIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthenticationTokenIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationTokenIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
