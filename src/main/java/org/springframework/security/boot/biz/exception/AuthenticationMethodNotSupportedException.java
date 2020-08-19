package org.springframework.security.boot.biz.exception;

/**
 * Authentication Method Not Supported Exception
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public class AuthenticationMethodNotSupportedException extends AuthenticationExceptionAdapter {
	
	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationMethodNotSupportedException</code> with the
	 * specified message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationMethodNotSupportedException(String msg) {
		super(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED, msg);
	}

	/**
	 * Constructs an <code>AuthenticationMethodNotSupportedException</code> with the
	 * specified message and root cause.
	 *
	 * @param msg the detail message
	 * @param t root cause
	 */
	public AuthenticationMethodNotSupportedException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED, msg, t);
	}
	
}
