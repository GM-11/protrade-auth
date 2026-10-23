package protrader.authentication.google;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** The Google verifier against a locally signed RS256 token and a local key (no network). */
class GoogleIdTokenVerifierTest {

	private static final String CLIENT = "web-client.apps.googleusercontent.com";
	private static final String ANDROID = "android-client.apps.googleusercontent.com";

	private final KeyPair pair = rsa();
	private final NimbusGoogleIdTokenVerifier verifier = new NimbusGoogleIdTokenVerifier(
			() -> NimbusJwtDecoder.withPublicKey((RSAPublicKey) pair.getPublic()).build(), CLIENT, List.of(ANDROID));

	private static KeyPair rsa() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(2048);
			return g.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private JWTClaimsSet.Builder good() {
		return new JWTClaimsSet.Builder()
				.issuer("https://accounts.google.com")
				.audience(CLIENT)
				.subject("1234567890")
				.claim("email", "Person@Example.com")
				.claim("email_verified", true)
				.claim("name", "Pat Person")
				.issueTime(new Date())
				.expirationTime(new Date(System.currentTimeMillis() + 3_600_000));
	}

	private String sign(JWTClaimsSet claims, KeyPair with) {
		try {
			SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test").build(), claims);
			jwt.sign(new RSASSASigner((RSAPrivateKey) with.getPrivate()));
			return jwt.serialize();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private String sign(JWTClaimsSet.Builder claims) {
		return sign(claims.build(), pair);
	}

	private void assertRejected(String token, String nonce, boolean extra) {
		assertThatThrownBy(() -> verifier.verify(token, nonce, extra)).isInstanceOf(GoogleRejectedException.class);
	}

	@Test
	void validTokenYieldsTheIdentity() {
		GoogleIdentity id = verifier.verify(sign(good()), null, false);
		assertThat(id.sub()).isEqualTo("1234567890");
		assertThat(id.email()).isEqualTo("Person@Example.com");
		assertThat(id.name()).isEqualTo("Pat Person");
	}

	@Test
	void bareAccountsGoogleComIssuerIsAccepted() {
		assertThat(verifier.verify(sign(good().issuer("accounts.google.com")), null, false)).isNotNull();
	}

	@Test
	void wrongIssuerIsRejected() {
		assertRejected(sign(good().issuer("https://evil.example.com")), null, false);
		assertRejected(sign(good().issuer("https://accounts.google.com.evil.com")), null, false);
	}

	@Test
	void wrongAudienceIsRejected() {
		assertRejected(sign(good().audience("someone-elses-client")), null, false);
		assertRejected(sign(good().audience(List.of("a", "b"))), null, false);
	}

	@Test
	void extraAudiencesCountOnlyForTheIdTokenShape() {
		String android = sign(good().audience(ANDROID));
		assertRejected(android, null, false);
		assertThat(verifier.verify(android, null, true)).isNotNull();
		// empty config accepts nothing extra
		NimbusGoogleIdTokenVerifier none = new NimbusGoogleIdTokenVerifier(
				() -> NimbusJwtDecoder.withPublicKey((RSAPublicKey) pair.getPublic()).build(), CLIENT, List.of());
		assertThatThrownBy(() -> none.verify(android, null, true)).isInstanceOf(GoogleRejectedException.class);
	}

	@Test
	void emptyClientIdAcceptsNothing() {
		NimbusGoogleIdTokenVerifier unconfigured = new NimbusGoogleIdTokenVerifier(
				() -> NimbusJwtDecoder.withPublicKey((RSAPublicKey) pair.getPublic()).build(), "", List.of());
		assertThatThrownBy(() -> unconfigured.verify(sign(good().audience("")), null, true)).isInstanceOf(GoogleRejectedException.class);
	}

	@Test
	void unverifiedOrMissingEmailIsRejected() {
		assertRejected(sign(good().claim("email_verified", false)), null, false);
		assertRejected(sign(good().claim("email_verified", null)), null, false);
		assertRejected(sign(good().claim("email", null)), null, false);
	}

	@Test
	void missingSubjectIsRejected() {
		assertRejected(sign(good().subject(null)), null, false);
	}

	@Test
	void expiredIsRejectedBeyondTheSkew() {
		Date issued = new Date(System.currentTimeMillis() - 2 * 3_600_000);
		assertRejected(sign(good().issueTime(issued).expirationTime(new Date(System.currentTimeMillis() - 10 * 60_000))), null, false);
		// 30 s past expiry is inside the 60 s skew
		assertThat(verifier.verify(sign(good().issueTime(issued).expirationTime(new Date(System.currentTimeMillis() - 30_000))), null, false)).isNotNull();
	}

	@Test
	void nonceMustMatchWhenProvided() {
		String token = sign(good().claim("nonce", "abc123"));
		assertThat(verifier.verify(token, "abc123", true)).isNotNull();
		assertRejected(token, "other", true);
		assertRejected(sign(good()), "abc123", true); // token has none
		assertThat(verifier.verify(token, null, false)).isNotNull(); // code shape: not checked here
	}

	@Test
	void signatureFromAnotherKeyIsRejected() {
		assertRejected(sign(good().build(), rsa()), null, false);
		assertRejected("not.a.jwt", null, false);
	}

	@Test
	void keyFetchFailureIsUnavailableNotRejected() {
		JwtDecoder broken = token -> {
			throw new JwtException("Couldn't retrieve remote JWK set");
		};
		NimbusGoogleIdTokenVerifier offline = new NimbusGoogleIdTokenVerifier(() -> broken, CLIENT, List.of());
		assertThatThrownBy(() -> offline.verify("x.y.z", null, false)).isInstanceOf(GoogleUnavailableException.class);
	}
}
