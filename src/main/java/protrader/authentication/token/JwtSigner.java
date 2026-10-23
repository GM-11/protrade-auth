package protrader.authentication.token;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;

/** Signs access tokens exactly as the gateway's verifier wants them (see JwtVerifier for the rules). */
public final class JwtSigner {

	private final Ed25519Signer signer;
	private final JWSHeader header;
	private final String issuer;
	private final String audience;
	private final Duration ttl;
	private final Clock clock;

	public JwtSigner(JwtKeySet keys, String issuer, String audience, Duration ttl, Clock clock) {
		try {
			this.signer = new Ed25519Signer(keys.signingKey());
		} catch (JOSEException e) {
			throw new IllegalStateException("bad signing key", e);
		}
		this.header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(JOSEObjectType.JWT).keyID(keys.kid()).build();
		this.issuer = issuer;
		this.audience = audience;
		this.ttl = ttl;
		this.clock = clock;
	}

	public String sign(long accountId) {
		long now = clock.instant().getEpochSecond();
		// payload as a plain map so "aud" is a one-element array, like order_gateway/cmd/devtoken
		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("iss", issuer);
		claims.put("aud", List.of(audience));
		claims.put("sub", Long.toString(accountId));
		claims.put("iat", now);
		claims.put("nbf", now);
		claims.put("exp", now + ttl.toSeconds());
		JWSObject jws = new JWSObject(header, new Payload(claims));
		try {
			jws.sign(signer);
		} catch (JOSEException e) {
			throw new IllegalStateException("signing failed", e);
		}
		return jws.serialize();
	}
}
