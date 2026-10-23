package protrader.authentication.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

import protrader.authentication.token.JwtKeySet;
import protrader.authentication.token.JwtSigner;

/** Builds tokens the server should accept or reject, with the production signer where possible. */
public final class TestTokens {

	public static final String ISSUER = "protrader-identity";
	public static final String AUDIENCE = "order-gateway";

	private TestTokens() {
	}

	public static OctetKeyPair newKey(String kid) {
		try {
			return new OctetKeyPairGenerator(Curve.Ed25519).keyID(kid).generate();
		} catch (com.nimbusds.jose.JOSEException e) {
			throw new IllegalStateException(e);
		}
	}

	public static JwtKeySet keySet(OctetKeyPair key) {
		return new JwtKeySet(key, List.of());
	}

	public static String sign(OctetKeyPair key, String issuer, String audience, long accountId, Instant at, Duration ttl) {
		return new JwtSigner(keySet(key), issuer, audience, ttl, Clock.fixed(at, ZoneOffset.UTC)).sign(accountId);
	}

	public static String sign(OctetKeyPair key, long accountId) {
		return sign(key, ISSUER, AUDIENCE, accountId, Instant.now(), Duration.ofHours(1));
	}
}
