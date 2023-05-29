package com.lora.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 安全配置
 *
 * @author lora
 * @date 2023/05/24
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login").defaultSuccessUrl("/");
        http.csrf().disable();
        http.logout().logoutSuccessUrl("/");//点击注销后跳到首页
        //默认保存2周
        http.rememberMe().rememberMeParameter("remember");
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user_thomas = User.builder()
                .username("lora")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip2","vip3")
                .build();
        UserDetails user_root = User.builder()
                .username("root")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1", "vip2", "vip3")
                .build();
        UserDetails user_guest = User.builder()
                .username("guest")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1")
                .build();
        return new InMemoryUserDetailsManager(user_thomas, user_root, user_guest);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
