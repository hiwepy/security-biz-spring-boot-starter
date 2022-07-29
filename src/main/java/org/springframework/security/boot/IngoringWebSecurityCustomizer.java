package org.springframework.security.boot;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Ingore Security Resource Customizer
 * https://www.jb51.net/article/252040.htm
 */
public class IngoringWebSecurityCustomizer implements WebSecurityCustomizer {

    private final SecurityBizProperties bizProperties;

    public IngoringWebSecurityCustomizer(SecurityBizProperties bizProperties) {
        this.bizProperties = bizProperties;
    }

    @Override
    public void customize(WebSecurity web) {
        // 对过滤链按过滤器名称进行分组
        Map<Object, List<Map.Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet()
                .stream().collect(Collectors.groupingBy(Map.Entry::getValue, TreeMap::new, Collectors.toList()));

        List<Map.Entry<String, String>> noneEntries = groupingMap.get("anon");
        List<String> permitMatchers = new ArrayList<String>();
        if (!CollectionUtils.isEmpty(noneEntries)) {
            permitMatchers = noneEntries.stream().map(mapper -> {
                return mapper.getKey();
            }).collect(Collectors.toList());
        }
        web.ignoring().antMatchers(permitMatchers.toArray(new String[permitMatchers.size()]));
    }

}
