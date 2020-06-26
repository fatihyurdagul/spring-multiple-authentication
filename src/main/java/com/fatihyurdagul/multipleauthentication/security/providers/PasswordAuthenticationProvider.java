package com.fatihyurdagul.multipleauthentication.security.providers;

import com.fatihyurdagul.multipleauthentication.security.token.PasswordToken;
import com.sun.tools.javac.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

// Kullanıcı adı ve parola ile giriş için business logic
public class PasswordAuthenticationProvider implements AuthenticationProvider {
  
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String password = authentication.getCredentials().toString();
    String password2 = (String) authentication.getCredentials();
    
    // ProjectConfig sınıfında oluşturduğumuz kullanıcı bilgileri
    if (username.equals("fatih") && password.equals("12345")) {
      return new PasswordToken(username, password, List.of(() -> "read"));
    }
    // Eğer bilgiler uyuşmaz ise hata fırlat
    throw new BadCredentialsException("username or password is not correct");
  }
  
  // Eğer PasswordToken sınıfında bir token gelirse kabul et ve bilgileri kontrol et.
  @Override
  public boolean supports(Class<?> aClass) {
    return PasswordToken.class.equals(aClass);
  }
}
