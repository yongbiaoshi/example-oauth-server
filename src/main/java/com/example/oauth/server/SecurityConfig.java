package com.example.oauth.server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/resources/**", "/signup", "/about").permitAll()
                .antMatchers("/api/**").hasAnyRole("INVOKER", "ADMIN")
                .anyRequest().authenticated()
                .and().formLogin()
                .and().logout()
                .and().authorizeRequests().antMatchers("/oauth/token").permitAll()
        ;
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{bcrypt}$2a$10$Vbm6pzsUW7c6Ubx3gCVq.eNVfRbjNi9Xz0nezBt/WzwWUfBIzzIY2")
                .authorities("ROLE_ADMIN", "ROLE_USER")
                .and()
                .withUser("bob")
                .password("{bcrypt}$2a$10$ulm2b4rAJveJGehegOYNceujCLNWDxBFnoqpfv2E49HlEp31X3cZG")
                .authorities("ROLE_USER")
        ;
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    public static void main(String[] args) {
        String pwd = PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("abc123");
        System.out.println(pwd);
    }

}
