package protrader.authentication.google;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Exactly one shape: (code, code_verifier, redirect_uri) or (id_token, nonce?). */
public record GoogleAuthRequest(
		String code,
		@JsonProperty("code_verifier") String codeVerifier,
		@JsonProperty("redirect_uri") String redirectUri,
		@JsonProperty("id_token") String idToken,
		String nonce) {
}
