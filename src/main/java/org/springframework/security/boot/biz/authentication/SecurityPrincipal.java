package org.springframework.security.boot.biz.authentication;

import java.io.Serializable;
import java.util.Set;

/**
 * @author <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class SecurityPrincipal implements Cloneable, Serializable {

	/**
	 * 用户ID（用户来源表Id）
	 */
	protected String userid;
	/**
	 * 用户Key
	 */
	protected String userkey;
	/**
	 * 用户名称
	 */
	protected String username;
	/**
	 * 用户密码
	 */
	protected String password;
	/**
	 * 用户密码盐：用于密码加解密
	 */
	protected String salt;
	/**
	 * 用户秘钥：用于用户JWT加解密
	 */
	private String secret;
	/**
	 * 用户别名（昵称）
	 */
	private String alias;
	/**
	 * 用户拥有角色列表
	 */
	private Set<String> roles;
	/**
	 * 用户权限标记列表
	 */
	private Set<String> perms;
	/**
	 * 用户过期性 :true:没过期 false:过期
	 */
	protected boolean enabled = Boolean.TRUE;
	/**
	 * 用户锁定性 :true:未锁定 false:已锁定
	 */
	protected boolean accountNonLocked = Boolean.TRUE;
	/**
	 * 用户过期性 :true:没过期 false:过期
	 */
	protected boolean accountNonExpired = Boolean.TRUE;
	/**
	 * 凭证有效性 :true:凭证有效 false:凭证无效
	 */
	protected boolean credentialsNonExpired = Boolean.TRUE;

	public SecurityPrincipal() {
	}

	public SecurityPrincipal(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public String getUserid() {
		return userid;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

	public String getUserkey() {
		return userkey;
	}

	public void setUserkey(String userkey) {
		this.userkey = userkey;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public String getCredentialsSalt() {
		return username + salt;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public Set<String> getRoles() {
		return roles;
	}

	public void setRoles(Set<String> roles) {
		this.roles = roles;
	}

	public Set<String> getPerms() {
		return perms;
	}

	public void setPerms(Set<String> perms) {
		this.perms = perms;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}

	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}

	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}

	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}

	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SecurityPrincipal user = (SecurityPrincipal) o;
		if (userid != null ? !userid.equals(user.getUserid()) : user.getUserid() != null) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return userid != null ? userid.hashCode() : 0;
	}

	@Override
	public String toString() {
		return " User {" + "userid=" + userid + ", username='" + username + '\'' + ", password='" + password + '\''
				+ ", salt='" + salt + '\'' + ", enabled='" + enabled + '\'' + ", accountNonExpired=" + accountNonExpired
				+ ", credentialsNonExpired=" + credentialsNonExpired + ", accountNonLocked=" + accountNonLocked + '}';
	}

}
