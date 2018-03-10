package org.springframework.security.boot.biz.authentication.rest;

import java.util.Date;

import org.springframework.http.HttpStatus;

/**
 * Error model for interacting with client.
 * 
 * @author vladimir.stankovic
 *
 * Aug 3, 2016
 */
public class RestErrorResponse {
	
    // HTTP Response Status Code
    private final HttpStatus status;

    // General Error message
    private final String message;

    private final Date timestamp;

    protected RestErrorResponse(final String message, HttpStatus status) {
        this.message = message;
        this.status = status;
        this.timestamp = new java.util.Date();
    }

    public static RestErrorResponse of(final String message, HttpStatus status) {
        return new RestErrorResponse(message, status);
    }

    public Integer getStatus() {
        return status.value();
    }

    public String getMessage() {
        return message;
    }

    public Date getTimestamp() {
        return timestamp;
    }
}
