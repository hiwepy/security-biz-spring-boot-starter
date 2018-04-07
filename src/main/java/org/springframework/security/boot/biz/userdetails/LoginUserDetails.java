/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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
package org.springframework.security.boot.biz.userdetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

@SuppressWarnings("serial")
public class LoginUserDetails extends User {

	public LoginUserDetails(String username, String password, String... roles) {
		super(username, password, roleAuthorities(Arrays.asList(roles)));
	}
	
	public static Collection<? extends GrantedAuthority> roleAuthorities(List<String> roles){
		
		if (roles == null) { 
			throw new InsufficientAuthenticationException("User has no roles assigned");
		}
        List<GrantedAuthority> authorities = roles.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        
		return authorities;
	}
	
	public LoginUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	public LoginUserDetails(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
	}
	
}
