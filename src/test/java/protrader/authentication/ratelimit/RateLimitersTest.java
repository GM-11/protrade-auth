package protrader.authentication.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import protrader.authentication.config.AuthProperties;

class RateLimitersTest {

	private static AuthProperties props(int perEmailIp, int perEmail) {
		var rl = new AuthProperties.RateLimit(20, perEmailIp, perEmail, Duration.ofMinutes(15), List.of());
		return new AuthProperties(8081, "127.0.0.1", Duration.ofHours(1), Duration.ofDays(30), Duration.ofDays(90),
				Duration.ofSeconds(10), List.of(), rl, new AuthProperties.Jwt("i", "a", "", "", ""),
				new AuthProperties.Google("", "", List.of(), List.of(), "https://x"));
	}

	@Test
	void bucketMapsStayBoundedUnderAFloodOfDistinctEmails() {
		RateLimiters limiters = new RateLimiters(props(5, 50), 50);
		for (int i = 0; i < 2_000; i++) {
			String email = "victim-" + i + "@example.com";
			limiters.loginFailuresPerEmailIp().tryAcquire(email + "|203.0.113.1");
			limiters.loginFailuresPerEmail().tryAcquire(email);
		}
		assertThat(limiters.loginFailuresPerEmailIp().size()).isLessThanOrEqualTo(50);
		assertThat(limiters.loginFailuresPerEmail().size()).isLessThanOrEqualTo(50);
	}

	@Test
	void theProductionDefaultsGiveTheDocumentedWaits() {
		long[] now = {1_000_000L * 1_000_000_000L};
		RateLimiters limiters = new RateLimiters(props(5, 50), 100, () -> now[0]);
		TokenBuckets strict = limiters.loginFailuresPerEmailIp();
		TokenBuckets loose = limiters.loginFailuresPerEmail();
		for (int i = 0; i < 5; i++) {
			assertThat(strict.tryAcquire("k")).isZero();
		}
		assertThat(strict.tryAcquire("k")).isEqualTo(180); // 5 per 15 min = one per 3 min
		for (int i = 0; i < 50; i++) {
			assertThat(loose.tryAcquire("k")).isZero();
		}
		assertThat(loose.tryAcquire("k")).isEqualTo(18); // 50 per 15 min = one per 18 s
		now[0] += 18L * 1_000_000_000L;
		assertThat(loose.tryAcquire("k")).isZero();
	}

	@Test
	void settingsAreValidated() {
		assertThatThrownBy(() -> props(0, 50)).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> props(5, 0)).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> props(10, 5)).isInstanceOf(IllegalStateException.class).hasMessageContaining("at least");
		props(5, 5); // equal is fine
	}

	@Test
	void peekWaitTakesNothing() {
		TokenBuckets b = new TokenBuckets(1, 1 / 60.0, 10, System::nanoTime);
		assertThat(b.peekWait("k")).isZero();
		assertThat(b.tryAcquire("k")).isZero();
		assertThat(b.peekWait("k")).isBetween(1L, 60L);
		assertThat(b.peekWait("k")).isBetween(1L, 60L);
		assertThat(b.size()).isEqualTo(1);
	}
}
