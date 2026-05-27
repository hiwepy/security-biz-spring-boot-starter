/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.biz.userdetails;

import com.github.hiwepy.jwt.JwtPayload;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

import java.util.Map;

/**
 * Abstract JSON Web Token (JWT) Payload Repository
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public interface JwtPayloadRepository {

	/**
	 * Issue Jwt
	 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
	 * @param token Authentication Token
	 * @return Jwt String
	 */
	default String issueJwt(AbstractAuthenticationToken token) { 
		if(token.getPrincipal() instanceof SecurityPrincipal) {
			SecurityPrincipal principal = (SecurityPrincipal) token.getPrincipal();
			return this.issueJwt(principal);
		}
		return "";
	};
	
	default String issueJwt(SecurityPrincipal principal) { 
		return this.issueJwt(principal.getUid(), principal.getProfile());
	};
	
	default String issueJwt(String uid, Map<String, Object> claims) { 
		return "";
	};

	/**
	 * Check JWT 
	 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
	 * @param token Authentication Token
	 * @param checkExpiry Whether Check JWT expiration time
	 * @return Effective or not
	 * @throws AuthenticationException if Authentication Exception
	 */
	default boolean verify(AbstractAuthenticationToken token, boolean checkExpiry) throws AuthenticationException{
		return false;
	};
	
	default boolean verify(String token, boolean checkExpiry) throws AuthenticationException{
		return false;
	};

	/**
	 * Parser JWT 
	 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
	 * @param token Authentication Token
	 * @param checkExpiry Whether Check JWT expiration time
	 * @return Jwt Payload
	 */
	default JwtPayload getPayload(AbstractAuthenticationToken token, boolean checkExpiry){
		return null;
	};
	
	default JwtPayload getPayload(String token, boolean checkExpiry){
		return null;
	};
	
	/**
	 * Parser JWT 
	 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
	 * @param token Authentication Token
	 * @param checkExpiry Whether Check JWT expiration time
	 * @return Jwt Payload
	 */
	default UserProfilePayload getProfilePayload(AbstractAuthenticationToken token, boolean checkExpiry){

		// 利用登陆用户信息
		SecurityPrincipal principal = (SecurityPrincipal) token.getPrincipal();
		
		String tokenString = this.issueJwt(token);
		
		UserProfilePayload payload = principal.toPayload();
		payload.setToken(tokenString);
		
		return payload;
		
	};;
	
}
