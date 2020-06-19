package com.fatihyurdagul.multipleauthentication.security.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class OtpToken extends UsernamePasswordAuthenticationToken {
		public OtpToken(Object principal, Object credentials) {
				super(principal, credentials);
		}

		public OtpToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
				super(principal, credentials, authorities);
		}
}
