package org.springframework.security.boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.util.CollectionUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class })
@EnableConfigurationProperties({ SecurityBizProperties.class})
@Order(104)
public class SecurityBizAdapterAutoConfiguration extends WebSecurityConfigurerAdapter{

	private Pattern rolesPattern = Pattern.compile("roles\\[(\\S)\\]");
	private Pattern permsPattern = Pattern.compile("perms\\[(\\S)\\]");
	private Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S)\\]");
	
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private SecurityBizUpcProperties bizUpcProperties;
	
	@Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}


	@Bean
	@ConditionalOnMissingBean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	@Bean
	@ConditionalOnMissingBean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	protected HttpFirewall httpFirewall() {
		return new StrictHttpFirewall();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}
	  
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
    	
    	// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet().stream()
				.collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

		ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry
			registry = http.authorizeRequests();
		
		
		List<Entry<String, String>> noneEntries = groupingMap.get("anon");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> {
				return mapper.getKey();
			}).collect(Collectors.toList());
		}
		// 登录地址不拦截 
		permitMatchers.add(bizUpcProperties.getAuthc().getLoginUrlPatterns());
		
		//添加不需要认证的路径 
		registry.antMatchers(permitMatchers.toArray(new String[permitMatchers.size()])).permitAll();
		
		// https://www.jianshu.com/p/01498e0e0c83
		Set<Object> keySet = groupingMap.keySet();
		for (Object key : keySet) {
			// Ant表达式 = roles[xxx] 
			Matcher rolesMatcher = rolesPattern.matcher(key.toString());
			if (rolesMatcher.find()) {
				
				System.out.println("Found value: " + rolesMatcher.group(0));
				System.out.println("Found value: " + rolesMatcher.group(1));

				List<String> matchers = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// 角色
				String[] roles = StringUtils.split(rolesMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(roles)) {
					if (roles.length > 1) {
						// 如果用户具备给定角色中的某一个的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasAnyRole(roles);
					} else {
						// 如果用户具备给定角色的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasRole(roles[0]);
					}
				}
			}
			// Ant表达式 = perms[xxx] 
			Matcher permsMatcher = permsPattern.matcher(key.toString());
			if (permsMatcher.find()) {
				
				System.out.println("Found value: " + permsMatcher.group(0));
				System.out.println("Found value: " + permsMatcher.group(1));

				List<String> matchers = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// 权限标记
				String[] perms = StringUtils.split(permsMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(perms)) {
					if (perms.length > 1) {
						// 如果用户具备给定全权限的某一个的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasAnyAuthority(perms);
					} else {
						// 如果用户具备给定权限的话，就允许访问
						registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasAuthority(perms[0]);
					}
				}
			}
			// Ant表达式 = ipaddr[192.168.1.0/24] 
			Matcher ipMatcher = ipaddrPattern.matcher(key.toString());
			if (rolesMatcher.find()) {
				
				System.out.println("Found value: " + ipMatcher.group(0));
				System.out.println("Found value: " + ipMatcher.group(1));

				List<String> matchers = groupingMap.get(key.toString()).stream().map(mapper -> {
					return mapper.getKey();
				}).collect(Collectors.toList());
				// ipaddress
				String ipaddr = rolesMatcher.group(1);
				if (StringUtils.hasText(ipaddr)) {
					// 如果请求来自给定IP地址的话，就允许访问
					registry.antMatchers(matchers.toArray(new String[matchers.size()])).hasIpAddress(ipaddr);
				}
			}
		}
		
		//允许认证过的用户访问
		registry.anyRequest().authenticated();

    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
    	
    	// 对过滤链按过滤器名称进行分组
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet().stream()
				.collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));
    	
		List<Entry<String, String>> noneEntries = groupingMap.get("anon");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> {
				return mapper.getKey();
			}).collect(Collectors.toList());
		}
		// 登录地址不拦截 
		permitMatchers.add(bizUpcProperties.getAuthc().getLoginUrlPatterns());
		
    	web.ignoring().antMatchers(permitMatchers.toArray(new String[permitMatchers.size()]));
    	
    	//web.httpFirewall(httpFirewall)
    	
    }
	 

}
