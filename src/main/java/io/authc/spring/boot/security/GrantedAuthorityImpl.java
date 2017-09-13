/**
 * <p>Coyright (R) 2014 正方软件股份有限公司。<p>
 */
package io.jsonwebtoken.spring.boot.security;

import org.springframework.security.core.GrantedAuthority;

class GrantedAuthorityImpl implements GrantedAuthority{
    private String authority;

    public GrantedAuthorityImpl(String authority) {
        this.authority = authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return this.authority;
    }
}
