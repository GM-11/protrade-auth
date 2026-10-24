package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;

/** Per-IP limit: 20 requests a minute per endpoint (one token every 3 s), from the real socket peer. Time is the test's. */
@TestPropertySource(properties = {"auth.rate-limit.per-ip-per-minute=20", "auth.internal-port=0"})
class RateLimitTest extends IntegrationTest {

	@BeforeEach
	void refillEveryBucket() {
		clock.advance(Duration.ofMinutes(10));
	}

	@Test
	void the21stRequestInAMinuteIs429WithAnExactRetryAfterAndRefillsOnTheClock() {
		// an empty object is a cheap 422 (no BCrypt) but still counts
		for (int i = 1; i <= 20; i++) {
			assertThat(http().post("/v1/auth/login", "{}").status()).as("request %d", i).isEqualTo(422);
		}
		Http.Response limited = http().post("/v1/auth/login", "{}");
		assertThat(limited.status()).isEqualTo(429);
		assertThat(limited.error()).isEqualTo("rate_limited");
		assertThat(limited.json().get("message").asString()).isNotEmpty();
		assertThat(limited.headers().firstValue("Retry-After")).hasValue("3");
		assertThat(limited.headers().firstValue("Content-Type").orElse("")).startsWith("application/json");

		clock.advance(Duration.ofSeconds(2));
		Http.Response stillLimited = http().post("/v1/auth/login", "{}");
		assertThat(stillLimited.status()).isEqualTo(429);
		assertThat(stillLimited.headers().firstValue("Retry-After")).hasValue("1");

		clock.advance(Duration.ofSeconds(1)); // one token
		assertThat(http().post("/v1/auth/login", "{}").status()).isEqualTo(422);
		assertThat(http().post("/v1/auth/login", "{}").status()).isEqualTo(429);
	}

	@Test
	void eachEndpointHasItsOwnBudget() {
		for (int i = 0; i < 20; i++) {
			assertThat(http().post("/v1/auth/google/nonce", "").status()).isEqualTo(200);
		}
		assertThat(http().post("/v1/auth/google/nonce", "").status()).isEqualTo(429);
		// other limited endpoints are untouched
		assertThat(http().post("/v1/auth/signup", "{}").status()).isEqualTo(422);
		assertThat(http().post("/v1/auth/refresh", "{}").status()).isEqualTo(422);
	}

	@Test
	void aForgedForwardedForFromAnUntrustedPeerIsIgnored() {
		for (int i = 0; i < 20; i++) {
			Http.Response r = http().send("POST", "/v1/auth/google", "application/json", "{}".getBytes(), null,
					Map.of("X-Forwarded-For", "198.51.100." + (i + 1)));
			assertThat(r.status()).isEqualTo(422);
		}
		Http.Response r = http().send("POST", "/v1/auth/google", "application/json", "{}".getBytes(), null,
				Map.of("X-Forwarded-For", "198.51.100.200"));
		assertThat(r.status()).isEqualTo(429);
	}

	@Test
	void unlimitedEndpointsAreNotCounted() {
		for (int i = 0; i < 40; i++) {
			assertThat(http().get("/healthz").status()).isEqualTo(200);
			assertThat(http().get("/.well-known/jwks.json").status()).isEqualTo(200);
		}
	}
}
