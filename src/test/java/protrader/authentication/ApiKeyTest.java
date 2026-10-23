package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.annotation.JsonProperty;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Test 7: API keys and the gateway's key snapshot. */
class ApiKeyTest extends IntegrationTest {

	/** Mirrors order_gateway/auth KeySnapshot / KeyEntry, parsed with unknown fields disallowed like the gateway does. */
	record GatewayKey(@JsonProperty("key_id") String keyId, @JsonProperty("account_id") long accountId,
			@JsonProperty("secret_sha256") String secretSha256, boolean disabled, String label) {
	}

	record GatewaySnapshot(long version, List<GatewayKey> keys) {
	}

	private static final JsonMapper STRICT = JsonMapper.builder().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();

	private String token() {
		return newUser(uniqueEmail()).get("access_token").asString();
	}

	private Http.Response create(String token, String label) {
		return http().post("/v1/api-keys", "{\"label\":\"" + label + "\"}", token);
	}

	private long version() {
		return jdbc.sql("SELECT version FROM api_key_version").query(Long.class).single();
	}

	private static String sha256Hex(String s) throws Exception {
		return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	void createShowsTheSecretOnceAndStoresOnlyItsHash() throws Exception {
		String token = token();
		Http.Response r = create(token, "my bot");
		assertThat(r.status()).isEqualTo(201);
		JsonNode key = r.json();
		assertThat(key.propertyNames()).containsExactlyInAnyOrder("key_id", "secret", "label", "created_at");
		assertThat(key.get("key_id").asString()).matches("PK[A-Z2-7]{16}");
		assertThat(key.get("secret").asString()).matches("[A-Za-z0-9_-]{43}");
		assertThat(key.get("label").asString()).isEqualTo("my bot");
		assertThat(key.get("created_at").asString()).matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z");

		String stored = jdbc.sql("SELECT secret_sha256 FROM api_keys WHERE key_id = ?").param(key.get("key_id").asString()).query(String.class).single();
		assertThat(stored).isEqualTo(sha256Hex(key.get("secret").asString())).matches("[0-9a-f]{64}");

		Http.Response list = http().get("/v1/api-keys", token);
		assertThat(list.status()).isEqualTo(200);
		assertThat(list.body()).doesNotContain(key.get("secret").asString()).doesNotContain(stored);
		JsonNode first = list.json().get("keys").get(0);
		assertThat(first.propertyNames()).containsExactlyInAnyOrder("key_id", "label", "created_at", "disabled");
		assertThat(first.get("disabled").asBoolean()).isFalse();
	}

	@Test
	void listIsPerAccount() {
		String a = token();
		String b = token();
		String keyA = create(a, "a").json().get("key_id").asString();
		assertThat(http().get("/v1/api-keys", b).json().get("keys")).isEmpty();
		assertThat(http().get("/v1/api-keys", a).body()).contains(keyA);
	}

	@Test
	void anotherAccountsKeyAndAnUnknownKeyBothGive404KeyNotFound() {
		String a = token();
		String b = token();
		String keyA = create(a, "a").json().get("key_id").asString();
		Http.Response other = http().delete("/v1/api-keys/" + keyA, b);
		Http.Response unknown = http().delete("/v1/api-keys/PKDOESNOTEXIST0000", b);
		assertThat(other.status()).isEqualTo(404);
		assertThat(unknown.status()).isEqualTo(404);
		assertThat(other.error()).isEqualTo("key_not_found");
		assertThat(other.body()).isEqualTo(unknown.body());
		// and it was not disabled by the attempt
		assertThat(http().get("/v1/api-keys", a).json().get("keys").get(0).get("disabled").asBoolean()).isFalse();
	}

	@Test
	void disableKeepsTheRowBumpsTheVersionAndIsRepeatable() {
		String token = token();
		String keyId = create(token, "x").json().get("key_id").asString();
		long before = version();
		assertThat(http().delete("/v1/api-keys/" + keyId, token).status()).isEqualTo(204);
		assertThat(version()).isEqualTo(before + 1);
		assertThat(http().delete("/v1/api-keys/" + keyId, token).status()).isEqualTo(204);
		assertThat(version()).isEqualTo(before + 1); // nothing changed, nothing to announce
		JsonNode listed = http().get("/v1/api-keys", token).json().get("keys").get(0);
		assertThat(listed.get("key_id").asString()).isEqualTo(keyId);
		assertThat(listed.get("disabled").asBoolean()).isTrue();
	}

	@Test
	void createBumpsTheVersion() {
		String token = token();
		long before = version();
		create(token, "x");
		assertThat(version()).isEqualTo(before + 1);
	}

	@Test
	void labelAndKeyCountLimits() {
		String token = token();
		Http.Response tooLong = create(token, "x".repeat(61));
		assertThat(tooLong.status()).isEqualTo(422);
		assertThat(tooLong.json().get("field").asString()).isEqualTo("label");
		assertThat(create(token, "x".repeat(60)).status()).isEqualTo(201);
		assertThat(http().post("/v1/api-keys", "{}", token).status()).isEqualTo(201); // label is optional

		String keyId = null;
		for (int i = 0; i < 8; i++) {
			Http.Response r = create(token, "k" + i);
			assertThat(r.status()).isEqualTo(201);
			keyId = r.json().get("key_id").asString();
		}
		Http.Response over = create(token, "one too many");
		assertThat(over.status()).isEqualTo(422);
		assertThat(over.error()).isEqualTo("invalid_field");
		assertThat(over.json().get("field").asString()).isEqualTo("label");
		// disabled keys don't count against the cap
		assertThat(http().delete("/v1/api-keys/" + keyId, token).status()).isEqualTo(204);
		assertThat(create(token, "fits now").status()).isEqualTo(201);
	}

	@Test
	void userEndpointsNeedAToken() {
		assertThat(http().get("/v1/api-keys").status()).isEqualTo(401);
		assertThat(http().post("/v1/api-keys", "{}").status()).isEqualTo(401);
		assertThat(http().delete("/v1/api-keys/PKX", null).status()).isEqualTo(401);
	}

	@Test
	void snapshotRoundTripsThroughAStrictParserAndNeverHoldsSecrets() throws Exception {
		String token = token();
		Http.Response created = create(token, "bot");
		String keyId = created.json().get("key_id").asString();
		String secret = created.json().get("secret").asString();
		String disabledId = create(token, "old").json().get("key_id").asString();
		http().delete("/v1/api-keys/" + disabledId, token);

		Http.Response r = internal().get("/internal/v1/api-keys?if_newer_than=0");
		assertThat(r.status()).isEqualTo(200);
		assertThat(r.body()).doesNotContain(secret);
		GatewaySnapshot snap = STRICT.readValue(r.body(), GatewaySnapshot.class);
		assertThat(snap.version()).isEqualTo(version()).isGreaterThanOrEqualTo(1);

		GatewayKey live = snap.keys().stream().filter(k -> k.keyId().equals(keyId)).findFirst().orElseThrow();
		assertThat(live.secretSha256()).isEqualTo(sha256Hex(secret));
		assertThat(live.disabled()).isFalse();
		assertThat(live.label()).isEqualTo("bot");
		assertThat(live.accountId()).isGreaterThanOrEqualTo(1000);
		assertThat(snap.keys().stream().filter(k -> k.keyId().equals(disabledId)).findFirst().orElseThrow().disabled()).isTrue();

		// account_id is a JSON number, secret_sha256 exactly 64 hex, and the object has exactly the gateway's fields
		JsonNode entry = null;
		for (JsonNode k : r.json().get("keys")) {
			if (k.get("key_id").asString().equals(keyId)) {
				entry = k;
			}
		}
		assertThat(entry.get("account_id").isNumber()).isTrue();
		assertThat(entry.get("secret_sha256").asString()).matches("[0-9a-f]{64}");
		assertThat(entry.propertyNames()).containsExactlyInAnyOrder("key_id", "account_id", "secret_sha256", "disabled", "label");
		assertThat(r.json().propertyNames()).containsExactlyInAnyOrder("version", "keys");
		assertThat(r.body().length()).isLessThan(1 << 20);
	}

	@Test
	void snapshotIs304WhenTheCallerIsCurrentAndMissingOrBadParamMeansZero() {
		create(token(), "x");
		long current = version();
		Http.Response same = internal().get("/internal/v1/api-keys?if_newer_than=" + current);
		assertThat(same.status()).isEqualTo(304);
		assertThat(same.body()).isEmpty();
		assertThat(internal().get("/internal/v1/api-keys?if_newer_than=" + (current + 5)).status()).isEqualTo(304);
		assertThat(internal().get("/internal/v1/api-keys?if_newer_than=" + (current - 1)).status()).isEqualTo(200);
		assertThat(internal().get("/internal/v1/api-keys").status()).isEqualTo(200);
		assertThat(internal().get("/internal/v1/api-keys?if_newer_than=abc").status()).isEqualTo(200);
		assertThat(internal().get("/internal/v1/api-keys?if_newer_than=-4").status()).isEqualTo(200);
	}

	@Test
	void internalPathExistsOnlyOnTheInternalPort() {
		assertThat(http().get("/internal/v1/api-keys?if_newer_than=0").status()).isEqualTo(404);
		assertThat(http().get("/internal/v1/api-keys").error()).isEqualTo("not_found");
		assertThat(internal().get("/v1/me").status()).isEqualTo(404);
		assertThat(internal().get("/.well-known/jwks.json").status()).isEqualTo(404);
		assertThat(internal().post("/v1/auth/login", "{}").status()).isEqualTo(404);
		assertThat(internal().get("/healthz").status()).isEqualTo(200);
		assertThat(http().get("/healthz").status()).isEqualTo(200);
	}
}
