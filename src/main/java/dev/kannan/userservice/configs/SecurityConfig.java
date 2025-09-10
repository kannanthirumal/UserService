package dev.kannan.userservice.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    /*
        - got this configuration from spring security official docs
        - https://docs.spring.io/spring-security/reference/servlet/configuration/java.html
        - by default, spring security protects all the endpoints
        - I'm just customizing the end points that doesn't need any auth
    */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/signup").permitAll()
                        .anyRequest().permitAll() //.anyRequest().authenticated()
                        .and().cors().disable()
                        .csrf().disable()
                );

        return http.build();
    }
}
