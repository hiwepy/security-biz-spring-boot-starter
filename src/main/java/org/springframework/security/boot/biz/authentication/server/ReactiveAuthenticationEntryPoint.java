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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.utils.ReactiveSecurityResponseUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Post Request Authentication Entry Point
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class ReactiveAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private List<MatchedServerAuthenticationEntryPoint> entryPoints;
	
	public ReactiveAuthenticationEntryPoint(List<MatchedServerAuthenticationEntryPoint> entryPoints) {
		this.setEntryPoints(entryPoints);
	}

	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
		
		// 1、获取ServerHttpResponse、ServerHttpResponse
		ServerHttpRequest request = exchange.getRequest();
		ServerHttpResponse response = exchange.getResponse();
		
        if(CollectionUtils.isEmpty(entryPoints)) {
        	return ReactiveSecurityResponseUtils.handleFailure(request, response, e);
		} else {
			
			boolean isMatched = false;
			for (MatchedServerAuthenticationEntryPoint entryPoint : entryPoints) {
				
				if(entryPoint != null && entryPoint.supports(e)) {
					isMatched = true;
					return entryPoint.commence(exchange, e);
				}
				
			}
			if(!isMatched) {
				return ReactiveSecurityResponseUtils.handleFailure(request, response, e);
			}
		}
        
		return Mono.empty();
    }
     

	public MessageSourceAccessor getMessages() {
		return messages;
	}

	public List<MatchedServerAuthenticationEntryPoint> getEntryPoints() {
		return entryPoints;
	}

	public void setMessages(MessageSourceAccessor messages) {
		this.messages = messages;
	}

	public void setEntryPoints(List<MatchedServerAuthenticationEntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}
	
}