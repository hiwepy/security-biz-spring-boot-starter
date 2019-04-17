package org.springframework.security.boot.biz.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 */
public class IdentityCodeRequest {

	private String mobile;
	private String code;
	private String captcha;

	@JsonCreator
	public IdentityCodeRequest(@JsonProperty("mobile") String mobile, @JsonProperty("code") String code,
			@JsonProperty("captcha") String captcha) {
		this.mobile = mobile;
		this.code = code;
		this.captcha = captcha;
	}

	public String getMobile() {
		return mobile;
	}

	public void setMobile(String mobile) {
		this.mobile = mobile;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getCaptcha() {
		return captcha;
	}

	public void setCaptcha(String captcha) {
		this.captcha = captcha;
	}

}
