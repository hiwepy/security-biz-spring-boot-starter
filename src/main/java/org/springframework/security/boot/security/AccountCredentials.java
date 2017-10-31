/**
 * <p>Coyright (R) 2014 正方软件股份有限公司。<p>
 */
package io.jsonwebtoken.spring.boot.security;

class AccountCredentials {

    private String username;
    private String password;

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
}