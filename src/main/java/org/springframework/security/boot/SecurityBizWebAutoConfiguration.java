package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.property.SecurityAnonymousProperties;
import org.springframework.security.boot.biz.property.SecurityCorsProperties;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@AutoConfigureBefore( name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration"
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityBizProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class })
public class SecurityBizWebAutoConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    
    @Autowired
    private AbstractAuthenticationProcessingFilter authenticationFilter;
    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    private LogoutFilter logoutFilter;
    
    @Autowired
    private InvalidSessionStrategy invalidSessionStrategy;
    @Autowired
    private SessionInformationExpiredStrategy expiredSessionStrategy;
    
    @Bean
	@ConditionalOnMissingBean
    public InvalidSessionStrategy invalidSessionStrategy(){
		return new SimpleRedirectInvalidSessionStrategy(bizProperties.getRedirectUrl());
	}
    
    @Bean
	@ConditionalOnMissingBean
    public SessionInformationExpiredStrategy expiredSessionStrategy(){
		return new SimpleRedirectSessionInformationExpiredStrategy(bizProperties.getExpiredUrl());
	}
    
    
    protected CorsConfigurationSource corsConfigurationSource() {
    	CorsConfigurationSource s = new UrlBasedCorsConfigurationSource();
    	return s;
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
		
		HeadersConfigurer<HttpSecurity> headers = http.headers();
        
		if(null != bizProperties.getReferrerPolicy()) {
			headers.referrerPolicy(bizProperties.getReferrerPolicy()).and();
		}
        
		if(null != bizProperties.getFrameOptions()) {
			headers.frameOptions().disable();
		}
        
        
        http.csrf().disable();

        http.authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers("/static/**").permitAll() 	// 不拦截静态资源
                .antMatchers("/api/**").permitAll()  	// 不拦截对外API
                .anyRequest().authenticated();  	// 未匹配资源需要登陆后才可以访问
        
        http.logout()
        .clearAuthentication(true)
        .permitAll();  // 不拦截注销

        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);

        
        
        SecurityAnonymousProperties anonymous = bizProperties.getAnonymous();
        if(anonymous != null && anonymous.isEnabled()) {
        	http.anonymous().disable();
        }
        
       	SecurityCorsProperties cors = bizProperties.getCors();
    	SecurityCsrfProperties csrf = bizProperties.getCsrf();
       	SecurityLogoutProperties logout = bizProperties.getLogout();
        
        
        /*
        
        
        http.cors().configurationSource(corsConfigurationSource());
        
        
        http.csrf().disable();
        */
        
        
        http.servletApi().disable();

        SessionManagementConfigurer<HttpSecurity> sessionManagement = http.sessionManagement();
        
        sessionManagement.enableSessionUrlRewriting(false)
        .invalidSessionStrategy(invalidSessionStrategy)
        .invalidSessionUrl(bizProperties.getRedirectUrl())
        .sessionAuthenticationErrorUrl(bizProperties.getFailureUrl())
        //.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        
        if(bizProperties.isMultipleSession()) {
        	sessionManagement.maximumSessions(bizProperties.getMaximumSessions()).expiredSessionStrategy(expiredSessionStrategy).expiredUrl(bizProperties.getExpiredUrl()).maxSessionsPreventsLogin(bizProperties.isMaxSessionsPreventsLogin());
        }
        
        http.addFilter(authenticationFilter)
                .addFilterBefore(logoutFilter, LogoutFilter.class);

        if(StringUtils.hasText(bizProperties.getAntPattern())) {
        	http.antMatcher(bizProperties.getAntPattern());
        } else if(StringUtils.hasText(bizProperties.getMvcPattern())) {
        	http.mvcMatcher(bizProperties.getMvcPattern());
        } else if(StringUtils.hasText(bizProperties.getRegexPattern())) {
        	http.regexMatcher(bizProperties.getRegexPattern());
        }
        
    }
	
	@Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

}
