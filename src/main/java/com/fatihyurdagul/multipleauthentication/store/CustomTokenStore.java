package com.fatihyurdagul.multipleauthentication.store;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CustomTokenStore {
		List<String> tokenStore = new ArrayList();

		public void addToken(String token){
				tokenStore.add(token);
		}

		public boolean isExistToken(String token){
				return tokenStore.contains(token);
		}
}
