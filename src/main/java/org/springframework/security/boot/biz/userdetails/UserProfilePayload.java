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
	 * 用户ID（用户来源表Id）
	 */
	private String uid;
	/**
	 * 用户Key：用户业务表中的唯一ID
	 */
	private String ukey;
	/**
	 * 用户Code：用户业务表中的唯一编码
	 */
	private String ucode;
	/**
	 * 角色ID（角色表Id）
	 */
	private String rid;
	/**
	 * 角色Key：角色业务表中的唯一ID
	 */
	private String rkey;
	/**
	 * 角色Code：角色业务表中的唯一编码
	 */
	private String rcode;
	/**
	 * JWT Token
	 */
	private String token;
	/**
   	 * 用户是否完善信息
   	 */
    private boolean initial = Boolean.FALSE;
    /**
	 * User Profile
	 */
    private Map<String, Object> profile = new HashMap<>();
	/**
	 * User Roles
	 */
    private Set<String> roles = new HashSet<>();
    /**
	 * 用户权限标记列表
	 */
	private Set<String> perms = new HashSet<>();

}
