/** 
 * Copyright (C) 2020 杭州快定网络股份有限公司 (http://kding.com).
 * All Rights Reserved. 
 */
package org.springframework.security.boot.biz.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;
// https://www.jianshu.com/p/e013ca21d91d
public class ReactiveServerSecurityContextRepository implements ServerSecurityContextRepository {

	public static final String AUTHORIZATION = "X-Authorization";

	@Autowired
	private ReactiveAuthenticationManager authenticationManager;

	@Override
	public Mono<Void> save(ServerWebExchange serverWebExchange, SecurityContext securityContext) {
		return Mono.empty();
	}

	@Override
	public Mono<SecurityContext> load(ServerWebExchange serverWebExchange) {
		ServerHttpRequest request = serverWebExchange.getRequest();
		String token = request.getHeaders().getFirst(AUTHORIZATION);

		if (token != null) {
			Authentication auth = null;
			auth = new UsernamePasswordAuthenticationToken(token, token);
			return this.authenticationManager.authenticate(auth).map(SecurityContextImpl::new);
		} else {
			return Mono.empty();
		}
	}

}
