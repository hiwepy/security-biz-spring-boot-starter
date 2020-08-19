package org.springframework.security.boot.biz.exception;

/**
 * Authentication Token Expired Exception
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public class AuthenticationTokenExpiredException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AuthenticationTokenExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public AuthenticationTokenExpiredException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED, msg);
	}

	/**
	 * Constructs an <code>AuthenticationTokenExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AuthenticationTokenExpiredException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_TOKEN_EXPIRED, msg, t);
	}

}
