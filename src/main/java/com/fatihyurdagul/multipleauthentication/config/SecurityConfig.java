package com.fatihyurdagul.multipleauthentication.config;

import com.fatihyurdagul.multipleauthentication.security.filter.CustomAuthenticationFilter;
import com.fatihyurdagul.multipleauthentication.security.providers.OtpAuthenticationProvider;
import com.fatihyurdagul.multipleauthentication.security.providers.PasswordAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		CustomAuthenticationFilter filter;

		@Bean
		public PasswordAuthenticationProvider passwordProvider() {
				return new PasswordAuthenticationProvider();
		}

		@Bean
		public OtpAuthenticationProvider otpProvider() {
				return new OtpAuthenticationProvider();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
				auth.authenticationProvider(passwordProvider())
								.authenticationProvider(otpProvider());
		}

		@Override
		@Bean
		protected AuthenticationManager authenticationManager() throws Exception {
				return super.authenticationManager();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
				http.csrf().disable()
								.addFilterAt(filter, BasicAuthenticationFilter.class);
		}


}
