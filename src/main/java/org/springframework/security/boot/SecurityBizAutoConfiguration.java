package org.springframework.security.boot;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import hitool.core.lang3.time.DateFormats;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
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
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.*;
import org.springframework.security.boot.biz.IgnoreLogoutHandler;
import org.springframework.security.boot.biz.authentication.AuthorizationPermissionEvaluator;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.session.*;
import org.springframework.web.servlet.LocaleResolver;

import java.util.stream.Collectors;

/**
 *  基础对象初始化
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties({ SecurityBizProperties.class, SecuritySessionMgtProperties.class })
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
		return Jackson2ObjectMapperBuilder.json()
				.simpleDateFormat(DateFormats.DATE_LONGFORMAT)
				.failOnEmptyBeans(false)
				.failOnUnknownProperties(false)
				.featuresToEnable(MapperFeature.USE_GETTERS_AS_SETTERS, MapperFeature.ALLOW_FINAL_FIELDS_AS_MUTATORS).build();
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
	protected AuthenticationManager authenticationManager(ObjectProvider<AuthenticationProvider> authenticationProvider) {
    	ProviderManager authenticationManager = new ProviderManager(authenticationProvider.stream().collect(Collectors.toList()));
		authenticationManager.setEraseCredentialsAfterAuthentication(false);
		return authenticationManager;
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
	
	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
 		return new NullRememberMeServices();
 	}
	
	@Bean
	@ConditionalOnMissingBean
	public SessionRegistry sessionRegistry() {
 		return new SessionRegistryImpl();
 	}
	
	@Bean
	@ConditionalOnMissingBean
	public SessionInformationExpiredStrategy expiredSessionStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
 		return new SimpleRedirectSessionInformationExpiredStrategy(sessionMgtProperties.getFailureUrl());
 	}
	
	@Bean
	@ConditionalOnMissingBean
	public InvalidSessionStrategy invalidSessionStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				sessionMgtProperties.getFailureUrl());
		invalidSessionStrategy.setCreateNewSession(sessionMgtProperties.isAllowSessionCreation());
		return invalidSessionStrategy;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AccessDeniedHandler accessDeniedHandler() {
		AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
		return accessDeniedHandler;
	}

	@Bean
	@ConditionalOnMissingBean
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionAuthenticationStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
 		// Session 管理器配置参数
 		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new ChangeSessionIdAuthenticationStrategy();
 		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new SessionFixationProtectionStrategy();
 		} else if (SessionFixationPolicy.NEW_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
 			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
 			return sessionFixationProtectionStrategy;
 		} else {
 			return new NullAuthenticatedSessionStrategy();
 		}
 	}

}
