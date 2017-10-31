/**
 * <p>Coyright (R) 2014 正方软件股份有限公司。<p>
 */
package io.jsonwebtoken.spring.boot.security;

/**
 * 提供认证所需的用户信息
 *
 * @author ybin
 * @since 2017-03-08
 */
public class UserDetailsServiceCustom implements UserDetailsService {

    protected final Log logger = LogFactory.getLog(this.getClass());

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 1. 根据用户标识获取用户

        if (user == null) {
            logger.debug("can not find user: " + username);
            throw new UsernameNotFoundException("can not find user.");
        }

        // 2. 获取用户权限

        UserDetails userDetails = new JWTUserDetails(userId, username, password,
                enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);

        return userDetails;
    }

}