package protrader.authentication.token;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Body of login, refresh and Google sign-in (contract §3.1). */
public record LoginResponse(
		@JsonProperty("access_token") String accessToken,
		@JsonProperty("token_type") String tokenType,
		@JsonProperty("expires_in") long expiresIn,
		@JsonProperty("refresh_token") String refreshToken,
		@JsonProperty("account_id") String accountId) {
}
