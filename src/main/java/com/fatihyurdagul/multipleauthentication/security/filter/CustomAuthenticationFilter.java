package com.fatihyurdagul.multipleauthentication.security.filter;

import com.fatihyurdagul.multipleauthentication.OtpStore;
import com.fatihyurdagul.multipleauthentication.security.token.OtpToken;
import com.fatihyurdagul.multipleauthentication.security.token.PasswordToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Random;
import java.util.UUID;

@Component
public class CustomAuthenticationFilter extends OncePerRequestFilter {

		@Autowired
		AuthenticationManager manager;

		@Autowired
		OtpStore store;

		@Override
		protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
				String authorization = httpServletRequest.getHeader("Authorization");

				if (authorization == null || authorization.length() <= 0) {
						filterChain.doFilter(httpServletRequest, httpServletResponse);
						return;
				}
				String[] authorizationArray = authorization.split(" ");
				if (authorizationArray.length <= 0) return;
				String prefix = authorizationArray[0];

				String[] credentials = authorizationArray[1].split(":");
				String username = credentials[0];

				Authentication token;
				if (prefix.equals("password")) {
						String password = credentials[1];

						token = new PasswordToken(username, password);
						Authentication authenticated = manager.authenticate(token);

						// burada normalde kullanici icin one time password generate edip
						// herhangi bir yerde sakladiktan sonra kullaniciya mail veya sms ile
						// tek kullanimlik sifresi iletilmeli.
						String otpCode = String.valueOf(new Random().nextInt(9999) + 1000);

						store.addUsernameOtp(username, otpCode);
						// otp code'a bakip giris yapmayi deneyecegiz.
						System.out.println(otpCode);

				} else { // "otp"
						String otp = credentials[1];

						token = new OtpToken(username, otp);
						Authentication authenticated = manager.authenticate(token);

						httpServletResponse.setHeader("token", UUID.randomUUID().toString());

				}
		}

		@Override
		protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
				return !request.getServletPath().equals("/login");
		}
}
