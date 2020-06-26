package com.fatihyurdagul.multipleauthentication.config;

import com.fatihyurdagul.multipleauthentication.security.filter.CustomAuthenticationFilter;
import com.fatihyurdagul.multipleauthentication.security.filter.TokenAuthenticationFilter;
import com.fatihyurdagul.multipleauthentication.security.providers.OtpAuthenticationProvider;
import com.fatihyurdagul.multipleauthentication.security.providers.PasswordAuthenticationProvider;
import com.fatihyurdagul.multipleauthentication.security.providers.TokenAuthenticationProvider;
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
  
  // Login için Bütün istekleri yakalayıp kontrol edecek filtremiz.
  @Autowired
  CustomAuthenticationFilter loginFilter;
  
  // Loginden sonrası için token ile gelen istekleri kontrol eden filter
  @Autowired
  TokenAuthenticationFilter tokenFilter;
  
  // Kullanıcının normal kullanıcı adı ve parola ile girişini kontrol edecek mekanizma
  @Bean
  public PasswordAuthenticationProvider passwordProvider() {
    return new PasswordAuthenticationProvider();
  }
  
  // Kullanıcının ilk aşamayı geçtikten sonra sms veya mail ile gelen
  // 4 haneli şifreyi kontrol edecek mekanizma
  @Bean
  public OtpAuthenticationProvider otpProvider() {
    return new OtpAuthenticationProvider();
  }
  
  // Kullanıcının login işlemi bittikten sonra token ile gelen
  // isteklerinde tokenin doğruluğunu kontrol eden mekanizma
  @Bean
  public TokenAuthenticationProvider tokenAuthenticationProvider() {
    return new TokenAuthenticationProvider();
  }
  
  // İki farklı giriş yöntemini authentication managera ekliyoruz.
  // Son olarak token kontrolünü yapacak provideri ekliyoruz
  @Override
  protected void configure(AuthenticationManagerBuilder auth) {
    auth.authenticationProvider(passwordProvider())
    .authenticationProvider(otpProvider())
    .authenticationProvider(tokenAuthenticationProvider());
  }
  
  // Authentication Maanger'i filtre içerisinde kullanabilmek için context'e ekliyoruz.
  @Override
  @Bean
  protected AuthenticationManager authenticationManager() throws Exception {
    return super.authenticationManager();
  }
  
  // loginFilter : Filtremizi her istekte çalışabilmesi için
  // BasicAuthenticationFilter'in olduğu pozisyona koyuyoruz.
  // tokenFilter : Kullanıcı tokenı aldıktan sonra yapacağı istekler
  // için tokenin geçerli olup olmadığını kontrol eden filtremizi ekliyoruz.
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
    .authorizeRequests().anyRequest().authenticated().and()
    .addFilterAt(loginFilter, BasicAuthenticationFilter.class)
    .addFilterAfter(tokenFilter, BasicAuthenticationFilter.class);
  }
}
