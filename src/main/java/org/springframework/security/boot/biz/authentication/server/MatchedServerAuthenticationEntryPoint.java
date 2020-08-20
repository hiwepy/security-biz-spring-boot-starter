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
package org.springframework.security.boot.biz.authentication.server;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.boot.utils.ReactiveSecurityResponseUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public interface MatchedServerAuthenticationEntryPoint {
	
	/**
	 * Whether it is supported
	 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
	 * @param e  the authentication exception
	 * @return true or false
	 */
	public boolean supports(AuthenticationException e) ;
	
	/**
	 * Initiates the authentication flow
	 *
	 * @param exchange
	 * @param e
	 * @return {@code Mono<Void>} to indicate when the request for authentication is complete
	 */
	default Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e){
		
		// 1、获取ServerHttpResponse、ServerHttpResponse
		ServerHttpRequest request = exchange.getRequest();
		ServerHttpResponse response = exchange.getResponse();
		
		// 2、统一异常处理
		return ReactiveSecurityResponseUtils.handleFailure(request, response, e);
		
	};
	
}
