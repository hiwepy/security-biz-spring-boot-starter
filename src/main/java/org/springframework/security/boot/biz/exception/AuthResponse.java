package org.springframework.security.boot.biz.exception;

import java.util.ArrayList;

/**
 * Auth response for interacting with client.
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class AuthResponse {
	
    private final String code;
	
    private final String msg;
    
    private final Object data;

    protected AuthResponse(final String code, final String msg) {
        this.code = code;
        this.msg = msg;
        this.data = new ArrayList<>();
    }
    
    protected AuthResponse(final String code, final String msg, final Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
    
    public static AuthResponse of(final String code, final String msg) {
        return new AuthResponse(code, msg);
    }

    public static AuthResponse of(final String code, final String msg, final Object data) {
        return new AuthResponse(code, msg, data);
    }

	public String getCode() {
		return code;
	}

	public String getMsg() {
		return msg;
	}

	public Object getData() {
		return data;
	}
    
}
