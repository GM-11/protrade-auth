package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Test 1: verifies a real login token the way order_gateway/auth/jwt.go and jwks.go do, step by step,
 * with plain java.security (no Nimbus, no Spring), so a mistake in our signer can't hide in a shared library.
 */
class GatewayCompatibilityTest extends IntegrationTest {

	private static final JsonMapper JSON = JsonMapper.builder().build();
	private static final byte[] ED25519_X509_PREFIX = HexOf("302a300506032b6570032100");

	private static byte[] HexOf(String hex) {
		return java.util.HexFormat.of().parseHex(hex);
	}

	/** auth.ParseJWKS: OKP/Ed25519 keys, kid non-empty and unique, x = 32 raw bytes in unpadded base64url. */
	private Map<String, PublicKey> parseJwks(String body) throws Exception {
		JsonNode keys = JSON.readTree(body).get("keys");
		Map<String, PublicKey> out = new HashMap<>();
		for (JsonNode k : keys) {
			Set<String> fields = new HashSet<>();
			k.propertyNames().forEach(fields::add);
			assertThat(fields).containsExactlyInAnyOrder("kty", "crv", "kid", "use", "alg", "x");
			assertThat(k.get("kty").asString()).isEqualTo("OKP");
			assertThat(k.get("crv").asString()).isEqualTo("Ed25519");
			assertThat(k.get("use").asString()).isEqualTo("sig");
			assertThat(k.get("alg").asString()).isEqualTo("EdDSA");
			String kid = k.get("kid").asString();
			assertThat(kid).isNotEmpty();
			assertThat(out).doesNotContainKey(kid);
			assertThat(k.get("x").asString()).doesNotContain("=");
			byte[] raw = Base64.getUrlDecoder().decode(k.get("x").asString());
			assertThat(raw).hasSize(32);
			byte[] der = new byte[ED25519_X509_PREFIX.length + 32];
			System.arraycopy(ED25519_X509_PREFIX, 0, der, 0, ED25519_X509_PREFIX.length);
			System.arraycopy(raw, 0, der, ED25519_X509_PREFIX.length, 32);
			out.put(kid, KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der)));
		}
		assertThat(out).isNotEmpty();
		return out;
	}

	@Test
	void loginTokenPassesEveryCheckOfTheGatewayVerifier() throws Exception {
		Map<String, PublicKey> jwks = parseJwks(http().get("/.well-known/jwks.json").body());
		JsonNode login = newUser(uniqueEmail());
		String token = login.get("access_token").asString();

		// JWTVerifier.Verify
		assertThat(token.length()).isLessThanOrEqualTo(4096);
		String[] parts = token.split("\\.", -1);
		assertThat(parts).hasSize(3);
		JsonNode header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
		JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));

		assertThat(header.get("alg").asString()).isEqualTo("EdDSA"); // WithValidMethods
		assertThat(header.get("typ").asString()).isEqualTo("JWT");
		String kid = header.get("kid").asString();
		assertThat(kid).isNotEmpty();
		assertThat(jwks).containsKey(kid);

		Signature sig = Signature.getInstance("Ed25519");
		sig.initVerify(jwks.get(kid));
		sig.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
		assertThat(sig.verify(Base64.getUrlDecoder().decode(parts[2]))).as("signature").isTrue();

		long now = System.currentTimeMillis() / 1000;
		long leeway = 30;
		assertThat(claims.get("iss").asString()).isEqualTo("protrader-identity"); // WithIssuer
		JsonNode aud = claims.get("aud"); // WithAudience: string or array both parse in jwt/v5
		assertThat(aud.isArray() ? aud.get(0).asString() : aud.asString()).isEqualTo("order-gateway");
		assertThat(claims.has("exp")).as("WithExpirationRequired").isTrue();
		assertThat(claims.has("nbf")).as("claims.NotBefore != nil").isTrue();
		assertThat(claims.has("iat")).as("claims.IssuedAt != nil").isTrue();
		assertThat(claims.get("exp").isIntegralNumber() && claims.get("iat").isIntegralNumber() && claims.get("nbf").isIntegralNumber()).isTrue();
		long exp = claims.get("exp").asLong();
		long nbf = claims.get("nbf").asLong();
		long iat = claims.get("iat").asLong();
		assertThat(exp).isGreaterThan(now - leeway);
		assertThat(nbf).isLessThanOrEqualTo(now + leeway);
		assertThat(iat).isLessThanOrEqualTo(now + leeway);
		assertThat(exp - iat).isLessThanOrEqualTo(3600); // maxTokenLifetime

		String sub = claims.get("sub").asString(); // strconv.ParseUint, non-zero
		assertThat(Long.parseUnsignedLong(sub)).isNotZero();
		assertThat(sub).isEqualTo(login.get("account_id").asString());

		// no fat claims
		assertThat(claims.propertyNames()).containsExactlyInAnyOrder("iss", "aud", "sub", "iat", "nbf", "exp");
		assertThat(login.get("expires_in").asInt()).isEqualTo(3600);
		assertThat(login.get("token_type").asString()).isEqualTo("Bearer");
	}

	@Test
	void jwksIsStableAcrossCalls() {
		Http.Response a = http().get("/.well-known/jwks.json");
		Http.Response b = http().get("/.well-known/jwks.json");
		assertThat(a.body()).isEqualTo(b.body());
	}
}
