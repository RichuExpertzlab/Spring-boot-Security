package com.example.springsecurity;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	protected InMemoryUserDetailsManager configAuthentication() {
		
		List<UserDetails> users = new ArrayList<>();
		List<GrantedAuthority> adminAuthority = new ArrayList<>();
		adminAuthority.add(new SimpleGrantedAuthority("ADMIN"));
		UserDetails admin= new User("devs", "{noop}devs", adminAuthority);
		users.add(admin);
		
		List<GrantedAuthority> employeeAuthority = new ArrayList<>();
		adminAuthority.add(new SimpleGrantedAuthority("EMPLOYEE"));
		UserDetails employee= new User("ns", "{noop}ns", employeeAuthority);
		users.add(employee);
		
		List<GrantedAuthority> managerAuthority = new ArrayList<>();
		adminAuthority.add(new SimpleGrantedAuthority("MANAGER"));
		UserDetails manager= new User("vs", "{noop}vs", managerAuthority);
		users.add(manager);
		
		return new InMemoryUserDetailsManager(users);
	}
	@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
 
    http.authorizeHttpRequests(
    auth -> auth.requestMatchers("/home").permitAll()
        .requestMatchers("/welcome").authenticated()
                        .requestMatchers("/admin").hasAuthority("ADMIN")
                        .requestMatchers("/emp").hasAuthority("EMPLOYEE")
                        .requestMatchers("/mgr").hasAuthority("MANAGER")
                        .requestMatchers("/common").hasAnyAuthority("EMPLOYEE", "MANAGER")
                        .anyRequest().authenticated()
                         )
            .formLogin(formLogin -> formLogin
                    .defaultSuccessUrl("/welcome", true)
                    .permitAll()
            )
            .rememberMe(rememberMe -> rememberMe.key("AbcdEfghIjkl..."))
            .logout(logout -> logout.logoutUrl("/logout").permitAll());
 
    return http.build();
}}