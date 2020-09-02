package org.springframework.security.boot;

import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.server.ReactiveRequestContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.boot.biz.authentication.server.DefaultMatchedServerAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.server.DefaultMatchedServerAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.server.MatchedServerAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.server.MatchedServerAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.server.MatchedServerAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.server.ReactiveAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.server.ReactiveAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.server.ReactiveAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.server.ReactiveServerAccessDeniedHandler;
import org.springframework.security.boot.biz.authentication.server.ReactiveServerLogoutSuccessHandler;
import org.springframework.security.boot.biz.i18n.ReactiveLocaleContextFilter;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.server.i18n.LocaleContextResolver;

/**
 *  基础对象初始化
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Configuration
@AutoConfigureBefore(ReactiveSecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
public class ReactiveSecurityBizAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	protected ReactiveLocaleContextFilter localeContextFilter(LocaleContextResolver localeContextResolver) {
		return new ReactiveLocaleContextFilter(localeContextResolver);
	}
	
	@Bean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	@ConditionalOnMissingBean
	public ReactiveRequestContextFilter requestContextFilter() {
		return new ReactiveRequestContextFilter();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedServerAuthenticationFailureHandler defaultMatchedServerAuthenticationFailureHandler() {
		return new DefaultMatchedServerAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedServerAuthenticationEntryPoint defaultMatchedServerAuthenticationEntryPoint() {
		return new DefaultMatchedServerAuthenticationEntryPoint();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ServerAuthenticationEntryPoint serverAuthenticationEntryPoint(
			ObjectProvider<MatchedServerAuthenticationEntryPoint> entryPointProvider) {
		return new ReactiveAuthenticationEntryPoint(entryPointProvider.stream().collect(Collectors.toList()));
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler(
			ObjectProvider<MatchedServerAuthenticationSuccessHandler> successHandlerProvider) {
		return new ReactiveAuthenticationSuccessHandler(successHandlerProvider.stream().collect(Collectors.toList()));
	}

	@Bean
	@ConditionalOnMissingBean
	public ServerAuthenticationFailureHandler serverAuthenticationFailureHandler(
			ObjectProvider<MatchedServerAuthenticationFailureHandler> failureHandlerProvider) {
		return new ReactiveAuthenticationFailureHandler(failureHandlerProvider.stream().collect(Collectors.toList()));
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ReactiveServerAccessDeniedHandler serverAccessDeniedHandler() {
		return new ReactiveServerAccessDeniedHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ServerLogoutSuccessHandler serverLogoutSuccessHandler() {
		return new ReactiveServerLogoutSuccessHandler();
	}

}
