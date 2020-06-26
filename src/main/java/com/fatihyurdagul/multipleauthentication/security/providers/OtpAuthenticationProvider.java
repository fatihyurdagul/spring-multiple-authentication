package com.fatihyurdagul.multipleauthentication.security.providers;

import com.fatihyurdagul.multipleauthentication.store.OtpStore;
import com.fatihyurdagul.multipleauthentication.security.token.OtpToken;
import com.sun.tools.javac.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class OtpAuthenticationProvider implements AuthenticationProvider {
  
  @Autowired
  OtpStore store;
  
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    
    String username = authentication.getName(); // principal
    String otp = (String) authentication.getCredentials();
    
    // gelen 4 haneli şifre otpStore içerisinde var mı ?
    if (store.isValidOtp(username, otp)) {
      return new OtpToken(username, null, List.of(() -> "read"));
    }
    // Eğer bilgiler uyuşmaz ise hata fırlat
    throw new BadCredentialsException("otp is not valid");
  }
  
  // Otp Token türünde bir sınıf geldiyse işlem yap.
  @Override
  public boolean supports(Class<?> aClass) {
    return OtpToken.class.equals(aClass);
  }
}
