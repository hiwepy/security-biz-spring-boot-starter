package org.springframework.security.boot.biz.exception;

import org.springframework.security.authentication.AuthenticationServiceException;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 4, 2016
 */
public class AuthenticationMethodNotSupportedException extends AuthenticationServiceException {
    private static final long serialVersionUID = 3705043083010304496L;

    public AuthenticationMethodNotSupportedException(String msg) {
        super(msg);
    }
}
