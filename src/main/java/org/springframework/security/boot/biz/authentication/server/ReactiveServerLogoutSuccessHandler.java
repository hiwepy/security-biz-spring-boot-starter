package org.springframework.security.boot.biz.authentication.server;

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;

import com.alibaba.fastjson.JSONObject;

import reactor.core.publisher.Mono;

public class ReactiveServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	@Override
	public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		
		// ServerHttpRequest request = exchange.getExchange().getRequest();
		ServerHttpResponse response = exchange.getExchange().getResponse();
		
		logger.debug("Locale : {}" , LocaleContextHolder.getLocale());
		
		response.setStatusCode(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		
		String body = JSONObject.toJSONString(AuthResponse.of(AuthResponseCode.SC_AUTHC_LOGOUT.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_LOGOUT.getMsgKey())));
			
		DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
        
	}

}
