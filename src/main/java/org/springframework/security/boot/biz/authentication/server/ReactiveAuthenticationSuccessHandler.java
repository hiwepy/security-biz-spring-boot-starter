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

import java.util.List;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.boot.utils.ReactiveSecurityResponseUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import reactor.core.publisher.Mono;

public class ReactiveAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

	private List<MatchedServerAuthenticationSuccessHandler> successHandlers;
	
	public ReactiveAuthenticationSuccessHandler(List<MatchedServerAuthenticationSuccessHandler> successHandlers) {
		this.setSuccessHandlers(successHandlers);
	}
	
	@Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
       
		// 1、获取ServerHttpResponse、ServerHttpResponse
		ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
		ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
		
		if (CollectionUtils.isEmpty(successHandlers)) {
			
			return ReactiveSecurityResponseUtils.handleSuccess(request, response, authentication);
			
		} else {

			boolean isMatched = false;
			for (MatchedServerAuthenticationSuccessHandler successHandler : successHandlers) {

				if (successHandler != null && successHandler.supports(authentication)) {
					isMatched = true;
					return successHandler.onAuthenticationSuccess(webFilterExchange, authentication);
				}

			}
			if (!isMatched) {
				return ReactiveSecurityResponseUtils.handleSuccess(request, response, authentication);
			}
		}
		
		return Mono.empty();
        
    }

	


	public List<MatchedServerAuthenticationSuccessHandler> getSuccessHandlers() {
		return successHandlers;
	}

	public void setSuccessHandlers(List<MatchedServerAuthenticationSuccessHandler> successHandlers) {
		this.successHandlers = successHandlers;
	}
	
}
