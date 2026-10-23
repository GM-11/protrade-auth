package protrader.authentication.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.OptionalLong;
import java.util.regex.Pattern;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Verifies our own access tokens with the same rules as order_gateway/auth/jwt.go: EdDSA only,
 * kid in our key set, iss, aud, exp/nbf/iat all present, exp - iat <= 1 h, 30 s leeway,
 * sub a non-zero decimal id.
 */
public final class JwtVerifier {

	private static final Duration LEEWAY = Duration.ofSeconds(30);
	private static final Duration MAX_LIFETIME = Duration.ofHours(1);
	private static final int MAX_TOKEN_CHARS = 4096;
	private static final Pattern ACCOUNT_ID = Pattern.compile("[1-9][0-9]{0,18}");

	private final JwtKeySet keys;
	private final String issuer;
	private final String audience;
	private final Clock clock;

	public JwtVerifier(JwtKeySet keys, String issuer, String audience, Clock clock) {
		this.keys = keys;
		this.issuer = issuer;
		this.audience = audience;
		this.clock = clock;
	}

	/** The account id (the token's sub) if the token is valid, else empty. Never says why. */
	public OptionalLong verify(String token) {
		try {
			return verifyOrThrow(token);
		} catch (Exception e) {
			return OptionalLong.empty();
		}
	}

	private OptionalLong verifyOrThrow(String token) throws Exception {
		if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_CHARS) {
			return OptionalLong.empty();
		}
		SignedJWT jwt = SignedJWT.parse(token);
		JWSHeader header = jwt.getHeader();
		if (!JWSAlgorithm.EdDSA.equals(header.getAlgorithm())) {
			return OptionalLong.empty();
		}
		String kid = header.getKeyID();
		if (kid == null || kid.isEmpty()) {
			return OptionalLong.empty();
		}
		OctetKeyPair key = keys.publicKey(kid).orElse(null);
		if (key == null || !jwt.verify(new Ed25519Verifier(key))) {
			return OptionalLong.empty();
		}

		JWTClaimsSet claims = jwt.getJWTClaimsSet();
		List<String> aud = claims.getAudience();
		if (!issuer.equals(claims.getIssuer()) || aud == null || !aud.contains(audience)) {
			return OptionalLong.empty();
		}
		Date exp = claims.getExpirationTime();
		Date nbf = claims.getNotBeforeTime();
		Date iat = claims.getIssueTime();
		if (exp == null || nbf == null || iat == null) {
			return OptionalLong.empty();
		}
		Instant now = clock.instant();
		if (!now.minus(LEEWAY).isBefore(exp.toInstant())
				|| now.plus(LEEWAY).isBefore(nbf.toInstant())
				|| now.plus(LEEWAY).isBefore(iat.toInstant())) {
			return OptionalLong.empty();
		}
		if (Duration.between(iat.toInstant(), exp.toInstant()).compareTo(MAX_LIFETIME) > 0) {
			return OptionalLong.empty();
		}
		String sub = claims.getSubject();
		if (sub == null || !ACCOUNT_ID.matcher(sub).matches()) {
			return OptionalLong.empty();
		}
		return OptionalLong.of(Long.parseLong(sub));
	}
}
