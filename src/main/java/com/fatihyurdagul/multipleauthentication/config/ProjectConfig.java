package com.fatihyurdagul.multipleauthentication.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class ProjectConfig {
  
  @Bean
  public UserDetailsService inMemoryUserDetailsService() {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    // normal kullanici girişi için..
    UserDetails user = User.withUsername("fatih").password("12345").authorities("read").build();
    manager.createUser(user);
    
    return manager;
  }
  
  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }
}
