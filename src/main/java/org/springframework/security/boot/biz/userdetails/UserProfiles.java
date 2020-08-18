package org.springframework.security.boot.biz.userdetails;

public class UserProfiles {

	/**
	 * 用户描述Id
	 */
	public static final String ID = "id";
	/**
	 * 用户ID（用户来源表Id）
	 */
	public static final String USERID = "userid";
	/**
	 * 用户名
	 */
	public static final String USERNAME = "username";
	
	/**
	 * 用户Key：用户业务表中的唯一ID
	 */
	public static final String USERKEY = "userkey";
	/**
	 * 用户Code：用户业务表中的唯一编码
	 */
	public static final String USERCODE = "usercode";
	
	/**
	 * 用户别名（昵称）
	 */
	public static final String NICKNAME = "nickname";
	
	/**
	 * 用户头像：图片路径或图标样式
	 */
	public static final String AVATAR = "avatar";
	/**
	 * 手机号码
	 */
	public static final String PHONE = "phone";
	/**
	 * 电子邮箱
	 */
	public static final String EMAIL = "email";
	/**
	 * 性别：（M：男，F：女）
	 */
	public static final String GENDER = "gender";
	/**
	 * 出生日期
	 */
	public static final String BIRTHDAY = "birthday";
	/**
	 * 身份证号码
	 */
	public static final String IDCARD = "idcard";
	/**
	 * 用户年龄
	 */
	public static final String AGE = "age";
	/**
	 *用户身高
	 */
	public static final String HEIGHT = "height";
	/**
	 *用户体重
	 */
	public static final String WEIGHT = "weight";
	/**
	 * 用户简介
	 */
	public static final String INTRO = "intro";
	
	/**
	 * 用户密码盐：用于密码加解密
	 */
	public static final String SALT = "salt";
	/**
	 * 用户秘钥：用于用户JWT加解密
	 */
	public static final String SECRET = "secret";
	/**
	 * 用户角色ID
	 */
	public static final String ROLEID = "roleid";
	/**
	 * 用户角色Key
	 */
	public static final String ROLE = "role";
	/**
	 * 用户人脸识别ID
	 */
	public static final String FACEID = "faceId";
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
   	 * 用户是否首次登录
   	 */
	public static final String INITIAL = "initial";
    /**
	 * 用户是否扫脸登录
	 */
    public static final String FACED = "faced";
    
	/**
	 * 用户是否功能受限（false:无限制|true:有限制）
	 */
	public static final String RESTRICTED = "restricted";
	
}
