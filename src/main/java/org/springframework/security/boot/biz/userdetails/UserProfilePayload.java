/** 
 * Copyright (C) 2020 杭州快定网络股份有限公司 (http://kding.com).
 * All Rights Reserved. 
 */
package org.springframework.security.boot.biz.userdetails;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import lombok.Data;

@Data
public class UserProfilePayload {
	
	/**
	 * User ID
	 */
	private String uid;
	/**
	 * JWT Token
	 */
	private String token;
	/**
	 * JWT Sequence
	 */
	private String sequence;
    /**
	 * User Profile
	 */
    private Map<String, Object> profile = new HashMap<>();
	/**
	 * User Roles
	 */
    private Set<String> roles = new HashSet<>();
    /**
	 * User Permissions
	 */
    private Set<String> permissions = new HashSet<>();

}
