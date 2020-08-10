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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedServerAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import com.alibaba.fastjson.JSONObject;

import reactor.core.publisher.Mono;

public class ReactiveAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private List<MatchedServerAuthenticationSuccessHandler> successHandlers;
	
	public ReactiveAuthenticationSuccessHandler(List<MatchedServerAuthenticationSuccessHandler> successHandlers) {
		this.setSuccessHandlers(successHandlers);
	}
	
	@Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
       
		ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
		ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
		
		if (CollectionUtils.isEmpty(successHandlers)) {
			
			return this.writeJSONString(request, response, authentication);
			
		} else {

			boolean isMatched = false;
			for (MatchedServerAuthenticationSuccessHandler successHandler : successHandlers) {

				if (successHandler != null && successHandler.supports(authentication)) {
					isMatched = true;
					return successHandler.onAuthenticationSuccess(webFilterExchange, authentication);
				}

			}
			if (!isMatched) {
				return this.writeJSONString(request, response, authentication);
			}
		}
		
		return Mono.empty();
        
    }

	protected Mono<Void> writeJSONString(ServerHttpRequest request, ServerHttpResponse response,
			Authentication authentication) {

		response.setStatusCode(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		
		Map<String, Object> tokenMap = new HashMap<String, Object>(16);
		tokenMap.put("code", AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
		tokenMap.put("msg", messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey()));
		// 账号首次登陆标记
		if(SecurityPrincipal.class.isAssignableFrom(userDetails.getClass())) {
			SecurityPrincipal securityPrincipal = (SecurityPrincipal) userDetails;
			tokenMap.putAll(securityPrincipal.toClaims());
		} else {
			tokenMap.put("initial", false);
			tokenMap.put("nickname", "");
			tokenMap.put("usercode", "");
			tokenMap.put("userkey", "");
			tokenMap.put("userid", "");
		}
		tokenMap.put("perms", userDetails.getAuthorities());
		tokenMap.put("username", userDetails.getUsername());
		
        String body = JSONObject.toJSONString(tokenMap);

        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
		
	}


	public List<MatchedServerAuthenticationSuccessHandler> getSuccessHandlers() {
		return successHandlers;
	}

	public void setSuccessHandlers(List<MatchedServerAuthenticationSuccessHandler> successHandlers) {
		this.successHandlers = successHandlers;
	}
	
}
