package org.springframework.security.boot.biz.userdetails;

public class UserProfiles {

	/**
	 * 用户描述Id
	 */
	public static final String ID = "id";
	/**
	 * 用户ID（用户来源表Id）
	 */
	public static final String UID = "uid";
	/**
	 * 用户UUID（用户唯一ID）
	 */
	public static final String UUID = "uuid";
	/**
	 * 用户名
	 */
	public static final String UNAME = "uname";
	/**
	 * 用户Key：用户业务表中的唯一ID
	 */
	public static final String UKEY = "ukey";
	/**
	 * 用户Code：用户业务表中的唯一编码
	 */
	public static final String UCODE = "ucode";
	
	/**
	 * 角色ID（角色表Id）
	 */
	public static final String RID = "rid";
	/**
	 * 角色Key：角色业务表中的唯一ID
	 */
	public static final String RKEY = "rkey";
	/**
	 * 角色Code：角色业务表中的唯一编码
	 */
	public static final String RCODE = "rcode";
	/**
	 * 用户密码盐：用于密码加解密
	 */
	public static final String SALT = "salt";
	/**
	 * 用户秘钥：用于用户JWT加解密
	 */
	public static final String SECRET = "secret";
	/**
	 * 用户拥有角色列表
	 */
	public static final String ROLES = "roles";
	/**
	 * 用户权限标记列表
	 */
	public static final String PERMS = "perms";
	/**
	 * 用户数据
	 */
	public static final String PROFILE = "profile";
	/**
   	 * 用户是否完善信息
   	 */
	public static final String INITIAL = "initial";
	
}
