package org.springframework.security.boot;

import javax.servlet.http.HttpServletRequest;

import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.boot.biz.IgnoreLogoutHandler;
import org.springframework.security.boot.biz.authentication.AuthorizationPermissionEvaluator;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationFailureHandler;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.servlet.LocaleResolver;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *  基础对象初始化
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	protected LocaleContextFilter localeContextFilter(LocaleResolver localeResolver) {
		return new LocaleContextFilter(localeResolver);
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected HttpFirewall httpFirewall() {
		return new StrictHttpFirewall();
	}

	@Bean
	@ConditionalOnMissingBean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}

	@Bean
	@ConditionalOnMissingBean
	public GrantedAuthoritiesMapper authoritiesMapper() {
		return new NullAuthoritiesMapper();
	}

	@Bean
	@ConditionalOnMissingBean
	public PermissionEvaluator permissionEvaluator() {
		return new AuthorizationPermissionEvaluator();
	}

    @Bean
	@ConditionalOnMissingBean 
	public CaptchaResolver captchaResolver() {
		return new NullCaptchaResolver();
	}
    
    @Bean
   	@ConditionalOnMissingBean 
   	public LogoutHandler ignoreLogoutHandler() {
   		return new IgnoreLogoutHandler();
   	}

	@Bean
	@ConditionalOnMissingBean
	protected HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedAuthenticationFailureHandler defaultMatchedAuthenticationFailureHandler() {
		return new DefaultMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedAuthenticationEntryPoint defaultMatchedAuthenticationEntryPoint() {
		return new DefaultMatchedAuthenticationEntryPoint();
	}

}
