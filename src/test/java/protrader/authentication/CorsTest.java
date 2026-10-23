package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;

// no internal listener here: the context above already holds that port
@TestPropertySource(properties = {"auth.cors-allowed-origins=https://app.example.com", "auth.internal-port=0"})
class CorsTest extends IntegrationTest {

	@Test
	void allowedOriginGetsPreflightAnswerWithoutCredentials() {
		Http.Response r = http().send("OPTIONS", "/v1/me", null, null, null, Map.of(
				"Origin", "https://app.example.com",
				"Access-Control-Request-Method", "GET",
				"Access-Control-Request-Headers", "Authorization"));
		assertThat(r.status()).isEqualTo(200);
		assertThat(r.headers().firstValue("Access-Control-Allow-Origin")).hasValue("https://app.example.com");
		assertThat(r.headers().firstValue("Access-Control-Allow-Headers").orElse("")).contains("Authorization");
		assertThat(r.headers().firstValue("Access-Control-Allow-Credentials")).isEmpty();
	}

	@Test
	void otherOriginsGetNothing() {
		Http.Response r = http().send("OPTIONS", "/v1/me", null, null, null, Map.of(
				"Origin", "https://evil.example.com",
				"Access-Control-Request-Method", "GET"));
		assertThat(r.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
		Http.Response simple = http().send("GET", "/healthz", null, null, null, Map.of("Origin", "https://evil.example.com"));
		assertThat(simple.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
	}
}
