package dev.kannan.userservice.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/*
  - Added this bean snippet inside the "securityFilterChain" method
  - of the "SecurityOauthConfig" class
  - to prevent creation of multiple conflicting "SecurityFilterChain" beans
  - which caused the "Error creating bean with name 'springSecurityFilterChain'" exception
  - by ensuring only a single SecurityFilterChain bean is created for Spring Security configuration
*/

@Configuration
public class SecurityConfig {
    /*
        - got this configuration from spring security official docs
        - https://docs.spring.io/spring-security/reference/servlet/configuration/java.html
        - by default, spring security protects all the endpoints
        - I'm just customizing the end points that doesn't need any auth
    */

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/signup").permitAll()
//                        .anyRequest().permitAll()  // Or use `.authenticated()` if required
//                )
//                .cors().disable()
//                .csrf().disable();
//
//        return http.build();
//    }
}
