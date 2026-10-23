package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetKeyPair;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;
import protrader.authentication.support.TestTokens;
import tools.jackson.databind.JsonNode;

/** Test 6: /v1/me rejects everything that isn't a good token from our own key. */
class MeAuthTest extends IntegrationTest {

	private JsonNode serverKey() {
		return http().get("/.well-known/jwks.json").json().get("keys").get(0);
	}

	private void assertUnauthorized(Http.Response r) {
		assertThat(r.status()).isEqualTo(401);
		assertThat(r.error()).isEqualTo("unauthorized");
	}

	private static String b64(String s) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	@Test
	void noTokenGarbageAndBadSchemeAreUnauthorized() {
		assertUnauthorized(http().get("/v1/me"));
		assertUnauthorized(http().get("/v1/me", "garbage"));
		assertUnauthorized(http().get("/v1/me", "a.b.c"));
		assertUnauthorized(http().send("GET", "/v1/me", null, null, null, java.util.Map.of("Authorization", "Basic dXNlcjpwYXNz")));
	}

	@Test
	void expiredTokenIsUnauthorized() {
		JsonNode jwk = serverKey();
		OctetKeyPair other = TestTokens.newKey(jwk.get("kid").asString());
		String expired = TestTokens.sign(other, TestTokens.ISSUER, TestTokens.AUDIENCE, 1000, Instant.now().minus(Duration.ofHours(3)), Duration.ofHours(1));
		assertUnauthorized(http().get("/v1/me", expired));
	}

	@Test
	void tokenSignedWithADifferentKeyIsUnauthorized() {
		// same kid as the server's, so only the signature can give it away
		OctetKeyPair other = TestTokens.newKey(serverKey().get("kid").asString());
		assertUnauthorized(http().get("/v1/me", TestTokens.sign(other, 1000)));
		// and a kid the server has never heard of
		assertUnauthorized(http().get("/v1/me", TestTokens.sign(TestTokens.newKey("nope"), 1000)));
	}

	@Test
	void wrongAudienceOrIssuerIsUnauthorized() {
		OctetKeyPair other = TestTokens.newKey(serverKey().get("kid").asString());
		assertUnauthorized(http().get("/v1/me", TestTokens.sign(other, TestTokens.ISSUER, "somebody-else", 1000, Instant.now(), Duration.ofHours(1))));
		assertUnauthorized(http().get("/v1/me", TestTokens.sign(other, "evil-issuer", TestTokens.AUDIENCE, 1000, Instant.now(), Duration.ofHours(1))));
	}

	@Test
	void algNoneIsUnauthorized() {
		String kid = serverKey().get("kid").asString();
		long now = Instant.now().getEpochSecond();
		String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}");
		String payload = b64("{\"iss\":\"protrader-identity\",\"aud\":[\"order-gateway\"],\"sub\":\"1000\",\"iat\":" + now
				+ ",\"nbf\":" + now + ",\"exp\":" + (now + 3600) + "}");
		assertUnauthorized(http().get("/v1/me", header + "." + payload + "."));
		assertUnauthorized(http().get("/v1/me", header + "." + payload));
	}

	@Test
	void hs256SignedWithThePublicKeyAsSecretIsUnauthorized() throws Exception {
		JsonNode jwk = serverKey();
		byte[] publicKey = Base64.getUrlDecoder().decode(jwk.get("x").asString());
		long now = Instant.now().getEpochSecond();
		String claims = "{\"iss\":\"protrader-identity\",\"aud\":[\"order-gateway\"],\"sub\":\"1000\",\"iat\":" + now
				+ ",\"nbf\":" + now + ",\"exp\":" + (now + 3600) + "}";
		JWSObject jws = new JWSObject(
				new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).keyID(jwk.get("kid").asString()).build(),
				new Payload(claims));
		jws.sign(new MACSigner(publicKey));
		assertUnauthorized(http().get("/v1/me", jws.serialize()));
	}

	@Test
	void tokenForADeletedOrUnknownAccountIsUnauthorizedNotA500() {
		// valid signature is needed to get this far, so use a real login and then remove the account's rows
		String email = uniqueEmail();
		JsonNode login = newUser(email);
		long id = Long.parseLong(login.get("account_id").asString());
		jdbc.sql("DELETE FROM refresh_tokens WHERE account_id = ?").param(id).update();
		jdbc.sql("DELETE FROM accounts WHERE id = ?").param(id).update();
		assertUnauthorized(http().get("/v1/me", login.get("access_token").asString()));
	}
}
