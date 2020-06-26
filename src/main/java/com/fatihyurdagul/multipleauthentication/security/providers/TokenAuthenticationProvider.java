package com.fatihyurdagul.multipleauthentication.security.providers;

import com.fatihyurdagul.multipleauthentication.security.token.CustomToken;
import com.fatihyurdagul.multipleauthentication.store.CustomTokenStore;
import com.sun.tools.javac.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class TokenAuthenticationProvider implements AuthenticationProvider {
  @Autowired
  CustomTokenStore tokenStore;
  
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String token = authentication.getName();
    
    // gelen tokenin uygulama içinde sakladığımız tokenStore sınıfında var olup olmadığına bakacağız.
    if (tokenStore.isExistToken(token)) {
      return new CustomToken(token, null, List.of(() -> "read"));
    }
    throw new BadCredentialsException("Token is not valid");
  }
  
  // Sadece CustomToken ile gelen credential için çalış.
  @Override
  public boolean supports(Class<?> aClass) {
    return CustomToken.class.equals(aClass);
  }
}
