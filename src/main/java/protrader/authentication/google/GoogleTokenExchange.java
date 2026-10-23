package protrader.authentication.google;

/** Exchanges an authorization code (+ PKCE verifier) for the ID token, on our server. */
public interface GoogleTokenExchange {

	/** @return the raw {@code id_token}; throws {@link GoogleRejectedException} / {@link GoogleUnavailableException}. */
	String exchange(String code, String codeVerifier, String redirectUri);
}
