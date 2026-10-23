package protrader.authentication.google;

public interface GoogleIdTokenVerifier {

	/**
	 * @param nonce expected nonce, or null to skip the check
	 * @param allowExtraAudiences whether the Android/iOS client ids count (id_token shape only)
	 * @throws GoogleRejectedException for any token we don't accept
	 * @throws GoogleUnavailableException if Google's keys can't be fetched
	 */
	GoogleIdentity verify(String idToken, String nonce, boolean allowExtraAudiences);
}
