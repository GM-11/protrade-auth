package protrader.authentication.google;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Validates Google ID tokens: signature + expiry through a JwtDecoder on Google's JWKS (RS256,
 * 60 s skew), then iss, aud, sub, email, email_verified and the optional nonce explicitly.
 */
public class NimbusGoogleIdTokenVerifier implements GoogleIdTokenVerifier {

	private static final List<String> ISSUERS = List.of("https://accounts.google.com", "accounts.google.com");

	private final Supplier<JwtDecoder> decoder;
	private final String clientId;
	private final List<String> extraAudiences;

	public NimbusGoogleIdTokenVerifier(Supplier<JwtDecoder> decoder, String clientId, List<String> extraAudiences) {
		this.decoder = decoder;
		this.clientId = clientId;
		this.extraAudiences = extraAudiences;
	}

	@Override
	public GoogleIdentity verify(String idToken, String nonce, boolean allowExtraAudiences) {
		Jwt jwt;
		try {
			jwt = decoder.get().decode(idToken);
		} catch (BadJwtException e) {
			throw new GoogleRejectedException("id_token not valid: " + e.getClass().getSimpleName());
		} catch (JwtException e) {
			// a JwtException that isn't "bad token" means Google's key set could not be fetched
			throw new GoogleUnavailableException("cannot validate Google ID token", e);
		}

		String iss = jwt.getClaimAsString("iss");
		if (iss == null || !ISSUERS.contains(iss)) {
			throw new GoogleRejectedException("wrong iss");
		}
		List<String> aud = jwt.getAudience() == null ? List.of() : jwt.getAudience();
		if (!audienceAccepted(aud, allowExtraAudiences)) {
			throw new GoogleRejectedException("wrong aud");
		}
		String sub = jwt.getSubject();
		String email = jwt.getClaimAsString("email");
		if (sub == null || sub.isBlank() || email == null || email.isBlank()) {
			throw new GoogleRejectedException("missing sub/email");
		}
		Object verified = jwt.getClaim("email_verified");
		if (!(Boolean.TRUE.equals(verified) || "true".equals(verified))) {
			throw new GoogleRejectedException("email not verified");
		}
		if (nonce != null) {
			String tokenNonce = jwt.getClaimAsString("nonce");
			if (tokenNonce == null || !MessageDigest.isEqual(tokenNonce.getBytes(StandardCharsets.UTF_8), nonce.getBytes(StandardCharsets.UTF_8))) {
				throw new GoogleRejectedException("nonce mismatch");
			}
		}
		return new GoogleIdentity(sub, email, jwt.getClaimAsString("name"));
	}

	private boolean audienceAccepted(List<String> aud, boolean allowExtra) {
		if (!clientId.isEmpty() && aud.contains(clientId)) {
			return true;
		}
		// empty extra-audience config accepts nothing
		return allowExtra && extraAudiences.stream().anyMatch(aud::contains);
	}
}
