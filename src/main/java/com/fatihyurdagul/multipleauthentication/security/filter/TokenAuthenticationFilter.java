package com.fatihyurdagul.multipleauthentication.security.filter;

import com.fatihyurdagul.multipleauthentication.security.token.CustomToken;
import com.fatihyurdagul.multipleauthentication.store.CustomTokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

		AuthenticationManager manager;

		@Autowired
		public TokenAuthenticationFilter(@Lazy AuthenticationManager manager) {
				this.manager = manager;
		}

		@Override
		protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
				String token = httpServletRequest.getHeader("Authorization");
				if (token == null || token.length() <= 0) {
						filterChain.doFilter(httpServletRequest, httpServletResponse);
						return;
				}
				Authentication authToken = new CustomToken(token, null);

				Authentication authenticate = manager.authenticate(authToken);

				if (authenticate.isAuthenticated()) {
						SecurityContextHolder.getContext().setAuthentication(authenticate);
						filterChain.doFilter(httpServletRequest, httpServletResponse);
				} else {
						throw new BadCredentialsException("Token is not correct");
				}
		}

		@Override
		protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
				return request.getServletPath().equals("/login");
		}
}
