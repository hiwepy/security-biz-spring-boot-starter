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
package org.springframework.security.boot.biz.authentication;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedServerAuthenticationEntryPoint;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;

import com.alibaba.fastjson.JSONObject;

import reactor.core.publisher.Mono;

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
		
		ServerHttpRequest request = exchange.getRequest();
		ServerHttpResponse response = exchange.getResponse();
		
        if(CollectionUtils.isEmpty(entryPoints)) {
        	return this.writeJSONString(request, response, e);
		} else {
			
			boolean isMatched = false;
			for (MatchedServerAuthenticationEntryPoint entryPoint : entryPoints) {
				
				if(entryPoint != null && entryPoint.supports(e)) {
					isMatched = true;
					return entryPoint.commence(exchange, e);
				}
				
			}
			if(!isMatched) {
				return this.writeJSONString(request, response, e);
			}
		}
        
		return Mono.empty();
    }
    
    protected Mono<Void> writeJSONString(ServerHttpRequest request, ServerHttpResponse response, AuthenticationException e) {

    	logger.debug("Locale : {}" , LocaleContextHolder.getLocale());
		
		response.setStatusCode(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		String body = "{}";
		if (e instanceof UsernameNotFoundException) {
			body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_NOT_FOUND.getMsgKey(), e.getMessage())));
		} else if (e instanceof BadCredentialsException) {
			body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(), e.getMessage())));
		}  else if (e instanceof DisabledException) {
			body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_DISABLED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_DISABLED.getMsgKey(), e.getMessage())));
		}  else if (e instanceof LockedException) {
			body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_LOCKED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_LOCKED.getMsgKey(), e.getMessage())));	
		}  else if (e instanceof AccountExpiredException) {
			body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_USER_EXPIRED.getMsgKey(), e.getMessage())));	
		}  else if (e instanceof CredentialsExpiredException) {
			body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_CREDENTIALS_EXPIRED.getMsgKey(), e.getMessage())));	
		} else {
	        body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_FAIL.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_FAIL.getMsgKey())));
		}

		DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
		
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