package org.springframework.security.boot.biz.authentication.server;

import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;


public class ReactiveServerAccessDeniedHandler implements ServerAccessDeniedHandler {
	
	protected Logger logger = LoggerFactory.getLogger(getClass());
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	@Override
	public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {

		// 1、获取ServerHttpResponse
		ServerHttpResponse response = exchange.getResponse();
		
		// 2、设置状态码和响应头
		response.setStatusCode(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		
		// 3、国际化后的异常信息
		logger.debug("Locale : {}" , LocaleContextHolder.getLocale());
		String message = messages.getMessage(AuthResponseCode.SC_AUTHZ_FAIL.getMsgKey());
				
		// 4、输出JSON格式数据
		String body = JSONObject.toJSONString(AuthResponse.fail(message));
		DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
	}

}
