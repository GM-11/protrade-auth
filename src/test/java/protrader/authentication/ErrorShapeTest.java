package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.jupiter.api.Test;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;

/** Test 8: every failure leaves as {"error":...} JSON with the gateway's codes, never HTML. */
class ErrorShapeTest extends IntegrationTest {

	private Http.Response post(String contentType, byte[] body) {
		return http().send("POST", "/v1/auth/login", contentType, body, null);
	}

	private Http.Response postJson(String body) {
		return post("application/json", body.getBytes(StandardCharsets.UTF_8));
	}

	private void assertJsonError(Http.Response r, int status, String code) {
		assertThat(r.status()).as(r.body()).isEqualTo(status);
		assertThat(r.headers().firstValue("Content-Type").orElse("")).startsWith("application/json");
		assertThat(r.json().get("error").asString()).isEqualTo(code);
		assertThat(r.body()).doesNotContain("<html").doesNotContain("Exception");
	}

	@Test
	void wrongOrMissingContentTypeIs415() {
		assertJsonError(post("text/plain", "{}".getBytes(StandardCharsets.UTF_8)), 415, "content_type_must_be_json");
		assertJsonError(post("application/x-www-form-urlencoded", "a=b".getBytes(StandardCharsets.UTF_8)), 415, "content_type_must_be_json");
		assertJsonError(post(null, "{}".getBytes(StandardCharsets.UTF_8)), 415, "content_type_must_be_json");
	}

	@Test
	void jsonContentTypeWithCharsetIsAccepted() {
		Http.Response r = post("application/json; charset=utf-8", "{\"email\":\"nobody@example.com\",\"password\":\"whatever1\"}".getBytes(StandardCharsets.UTF_8));
		assertJsonError(r, 401, "bad_credentials");
	}

	@Test
	void bodyOver16KbIs413() {
		String big = "{\"email\":\"" + "a".repeat(17 * 1024) + "\",\"password\":\"x\"}";
		assertJsonError(postJson(big), 413, "request_too_large");
		String justUnder = "{\"email\":\"" + "a".repeat(16 * 1024 - 40) + "\",\"password\":\"x\"}";
		assertThat(postJson(justUnder).status()).isNotEqualTo(413);
	}

	@Test
	void unparseableJsonAndUnknownFieldsAreInvalidJson() {
		assertJsonError(postJson("{"), 400, "invalid_json");
		assertJsonError(postJson(""), 400, "invalid_json");
		assertJsonError(postJson("not json"), 400, "invalid_json");
		assertJsonError(postJson("[]"), 400, "invalid_json");
		assertJsonError(postJson("null"), 400, "invalid_json");
		assertJsonError(postJson("{\"email\":\"a@b.com\",\"password\":\"x\",\"surprise\":1}"), 400, "invalid_json");
		assertJsonError(postJson("{\"email\":12345,\"password\":\"x\"}"), 400, "invalid_json");
	}

	@Test
	void dataAfterTheJsonObjectIsMalformedJson() {
		assertJsonError(postJson("{\"email\":\"a@b.com\",\"password\":\"x\"} {}"), 400, "malformed_json");
		assertJsonError(postJson("{\"email\":\"a@b.com\",\"password\":\"x\"} garbage"), 400, "malformed_json");
		assertJsonError(postJson("{\"email\":\"a@b.com\",\"password\":\"x\"}{"), 400, "malformed_json");
		// trailing whitespace is not data
		assertThat(postJson("{\"email\":\"a@b.com\",\"password\":\"x\"}  \n").status()).isEqualTo(401);
	}

	@Test
	void errorBodyNeverEchoesTheRequest() {
		Http.Response r = postJson("{\"email\":\"a@b.com\",\"password\":\"hunter2-secret\",\"surprise\":1}");
		assertThat(r.body()).doesNotContain("hunter2-secret");
	}

	@Test
	void unknownPathsAndWrongMethodsAreJson() {
		assertJsonError(http().get("/nope"), 404, "not_found");
		assertJsonError(http().get("/v1/auth/login", null), 401, "unauthorized"); // GET isn't a public route
		assertJsonError(http().send("PUT", "/healthz", null, null, null), 405, "method_not_allowed");
		assertJsonError(http().get("/v1/me"), 401, "unauthorized");
	}

	@Test
	void jwksHasExactlyTheGatewaysFieldsAndIsCacheable() {
		Http.Response r = http().get("/.well-known/jwks.json");
		assertThat(r.status()).isEqualTo(200);
		assertThat(r.headers().firstValue("Cache-Control").orElse("")).contains("public").contains("max-age=300");
		assertThat(r.json().propertyNames()).containsExactly("keys");
		var key = r.json().get("keys").get(0);
		assertThat(key.propertyNames()).containsExactlyInAnyOrder("kty", "crv", "kid", "use", "alg", "x");
		assertThat(key.get("kty").asString()).isEqualTo("OKP");
		assertThat(key.get("crv").asString()).isEqualTo("Ed25519");
		assertThat(key.get("use").asString()).isEqualTo("sig");
		assertThat(key.get("alg").asString()).isEqualTo("EdDSA");
		assertThat(java.util.Base64.getUrlDecoder().decode(key.get("x").asString())).hasSize(32);
		assertThat(r.body()).doesNotContain("\"d\"");
	}

	@Test
	void healthAndReadiness() {
		assertThat(http().get("/healthz").status()).isEqualTo(200);
		assertThat(http().get("/readyz").status()).isEqualTo(200);
	}

	@Test
	void noCorsHeadersWhenNoOriginsAreConfigured() {
		Http.Response r = http().send("GET", "/healthz", null, null, null, Map.of("Origin", "https://app.example.com"));
		assertThat(r.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
	}
}
