package org.springframework.security.boot.biz.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Authentication Method Not Supported Exception
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public class AuthenticationMethodNotSupportedException extends AuthenticationException {
	
	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationMethodNotSupportedException</code> with the
	 * specified message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationMethodNotSupportedException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AuthenticationMethodNotSupportedException</code> with the
	 * specified message and root cause.
	 *
	 * @param msg the detail message
	 * @param t root cause
	 */
	public AuthenticationMethodNotSupportedException(String msg, Throwable t) {
		super(msg, t);
	}
	
}
