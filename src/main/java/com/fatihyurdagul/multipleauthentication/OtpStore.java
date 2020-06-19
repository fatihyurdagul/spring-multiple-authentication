package com.fatihyurdagul.multipleauthentication;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class OtpStore {
		Map<String, String> userOtp = new HashMap<>();

		public void addUsernameOtp(String username, String otp) {
				userOtp.put(username, otp);
		}

		public boolean isValidOtp(String username, String otp) {
				if (userOtp.containsKey(username)) {
						String otpPassword = userOtp.get(username);
						return otpPassword.equals(otp);
				}
				return false;
		}
}
