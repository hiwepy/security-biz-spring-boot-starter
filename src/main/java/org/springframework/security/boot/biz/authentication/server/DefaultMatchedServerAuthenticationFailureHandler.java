package org.springframework.security.boot.biz.authentication.server;

import org.springframework.security.boot.biz.exception.*;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

/**
 * Post认证请求失败后的处理实现
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class DefaultMatchedServerAuthenticationFailureHandler  implements MatchedServerAuthenticationFailureHandler {

	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), AuthenticationMethodNotSupportedException.class,
				AuthenticationCaptchaNotFoundException.class, AuthenticationCaptchaIncorrectException.class,
				AuthenticationTokenNotFoundException.class, AuthenticationTokenIncorrectException.class,
				AuthenticationTokenExpiredException.class);
	}

}
