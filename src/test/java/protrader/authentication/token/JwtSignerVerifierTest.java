package protrader.authentication.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.OptionalLong;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;

import protrader.authentication.support.TestTokens;

class JwtSignerVerifierTest {

	private static final Instant NOW = Instant.parse("2026-10-23T10:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

	private final OctetKeyPair key = TestTokens.newKey("k1");
	private final JwtKeySet keys = new JwtKeySet(key, List.of());
	private final JwtSigner signer = new JwtSigner(keys, "iss", "aud", Duration.ofHours(1), CLOCK);
	private final JwtVerifier verifier = new JwtVerifier(keys, "iss", "aud", CLOCK);

	@Test
	void roundTrip() {
		assertThat(verifier.verify(signer.sign(1042))).isEqualTo(OptionalLong.of(1042));
	}

	@Test
	void tamperedPayloadFails() {
		String[] p = signer.sign(1042).split("\\.");
		String forged = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
				("{\"iss\":\"iss\",\"aud\":[\"aud\"],\"sub\":\"1\",\"iat\":" + NOW.getEpochSecond() + ",\"nbf\":" + NOW.getEpochSecond()
						+ ",\"exp\":" + (NOW.getEpochSecond() + 3600) + "}").getBytes());
		assertThat(verifier.verify(p[0] + "." + forged + "." + p[2])).isEmpty();
	}

	@Test
	void tamperedSignatureFails() {
		String t = signer.sign(1042);
		int sigStart = t.lastIndexOf('.') + 1;
		char first = t.charAt(sigStart);
		String bad = t.substring(0, sigStart) + (first == 'A' ? 'B' : 'A') + t.substring(sigStart + 1);
		assertThat(verifier.verify(bad)).isEmpty();
		assertThat(verifier.verify(t.substring(0, t.lastIndexOf('.') + 1))).isEmpty();
	}

	@Test
	void missingKidFails() throws Exception {
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).build(), new Payload(claims(NOW, 3600)));
		jws.sign(new Ed25519Signer(key));
		assertThat(verifier.verify(jws.serialize())).isEmpty();
	}

	@Test
	void requiresIssuedAtNotBeforeAndExpiry() throws Exception {
		long t = NOW.getEpochSecond();
		for (String missing : List.of("iat", "nbf", "exp")) {
			var claims = new java.util.LinkedHashMap<String, Object>(claims(NOW, 3600));
			claims.remove(missing);
			assertThat(verifier.verify(sign(claims))).as("without " + missing).isEmpty();
		}
		assertThat(verifier.verify(sign(claims(NOW, 3600)))).isPresent();
		assertThat(t).isPositive();
	}

	@Test
	void lifetimeOverOneHourFails() throws Exception {
		assertThat(verifier.verify(sign(claims(NOW, 3600)))).isPresent();
		assertThat(verifier.verify(sign(claims(NOW, 3601)))).isEmpty();
	}

	@Test
	void expiryAndLeeway() {
		String token = signer.sign(7); // exp = NOW + 1 h
		Instant exp = NOW.plus(Duration.ofHours(1));
		assertThat(at(exp.minusSeconds(1)).verify(token)).isPresent();
		assertThat(at(exp.plusSeconds(20)).verify(token)).isPresent(); // inside the 30 s leeway
		assertThat(at(exp.plusSeconds(40)).verify(token)).isEmpty();
	}

	private JwtVerifier at(Instant now) {
		return new JwtVerifier(keys, "iss", "aud", Clock.fixed(now, ZoneOffset.UTC));
	}

	@Test
	void tokenFromTheFutureBeyondLeewayFails() {
		JwtVerifier early = new JwtVerifier(keys, "iss", "aud", Clock.fixed(NOW.minusSeconds(60), ZoneOffset.UTC));
		assertThat(early.verify(signer.sign(7))).isEmpty();
		JwtVerifier slightlyEarly = new JwtVerifier(keys, "iss", "aud", Clock.fixed(NOW.minusSeconds(10), ZoneOffset.UTC));
		assertThat(slightlyEarly.verify(signer.sign(7))).isPresent();
	}

	@Test
	void badSubjectFails() throws Exception {
		for (String sub : List.of("0", "-5", "abc", "", "00012", "1.5", "99999999999999999999")) {
			var claims = new java.util.LinkedHashMap<String, Object>(claims(NOW, 3600));
			claims.put("sub", sub);
			assertThat(verifier.verify(sign(claims))).as("sub " + sub).isEmpty();
		}
	}

	@Test
	void issuerAndAudienceMustMatch() {
		assertThat(new JwtVerifier(keys, "other", "aud", CLOCK).verify(signer.sign(7))).isEmpty();
		assertThat(new JwtVerifier(keys, "iss", "other", CLOCK).verify(signer.sign(7))).isEmpty();
	}

	@Test
	void oversizedTokenFails() {
		assertThat(verifier.verify("a".repeat(4097))).isEmpty();
		assertThat(verifier.verify("")).isEmpty();
		assertThat(verifier.verify(null)).isEmpty();
	}

	@Test
	void audienceIsAOneElementArray() {
		String payload = new String(java.util.Base64.getUrlDecoder().decode(signer.sign(7).split("\\.")[1]));
		assertThat(payload).contains("\"aud\":[\"aud\"]");
	}

	@Test
	void retiredKeyVerifiesWhileInTheSetAndStopsOnceRemoved() {
		OctetKeyPair old = TestTokens.newKey("old");
		String oldToken = new JwtSigner(new JwtKeySet(old, List.of()), "iss", "aud", Duration.ofHours(1), CLOCK).sign(55);

		JwtKeySet rotated = new JwtKeySet(key, List.of(old.toPublicJWK()));
		assertThat(new JwtVerifier(rotated, "iss", "aud", CLOCK).verify(oldToken)).isEqualTo(OptionalLong.of(55));
		assertThat(rotated.jwks().toString()).contains("old").contains("k1").doesNotContain("\"d\"");

		assertThat(new JwtVerifier(keys, "iss", "aud", CLOCK).verify(oldToken)).isEmpty();
	}

	@Test
	void duplicateKidsAreRejected() {
		org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
				() -> new JwtKeySet(key, List.of(TestTokens.newKey("k1").toPublicJWK())));
	}

	private java.util.Map<String, Object> claims(Instant at, long lifetimeSeconds) {
		long now = at.getEpochSecond();
		var m = new java.util.LinkedHashMap<String, Object>();
		m.put("iss", "iss");
		m.put("aud", List.of("aud"));
		m.put("sub", "1042");
		m.put("iat", now);
		m.put("nbf", now);
		m.put("exp", now + lifetimeSeconds);
		return m;
	}

	private String sign(java.util.Map<String, Object> claims) throws Exception {
		JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k1").build(), new Payload(claims));
		jws.sign(new Ed25519Signer(key));
		return jws.serialize();
	}
}
