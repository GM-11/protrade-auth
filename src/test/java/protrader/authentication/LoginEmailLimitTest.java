package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;

/**
 * Login failure limits, with time under the test's control (FakeRateLimitClock). Window 15 min, strict 3 per
 * (email, IP) and loose 9 per email, so one strict token refills every 300 s and one loose token every 100 s.
 * (The production defaults 5 and 50 are checked in RateLimitersTest; here small numbers keep the BCrypt
 * work down.) 127.0.0.1 is a trusted proxy so that tests can pick the "client" IP with X-Forwarded-For.
 */
@TestPropertySource(properties = {
		"auth.rate-limit.login-failures-per-email-ip=3",
		"auth.rate-limit.login-failures-per-email=9",
		"auth.rate-limit.login-failure-window=15m",
		"auth.rate-limit.trusted-proxy-cidrs=127.0.0.1/32",
		"auth.internal-port=0"})
class LoginEmailLimitTest extends IntegrationTest {

	private Http.Response login(String email, String password) {
		return http().post("/v1/auth/login", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}");
	}

	/** Logs in as if from the given client IP. */
	private Http.Response loginFrom(String ip, String email, String password) {
		return http().send("POST", "/v1/auth/login", "application/json",
				("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}").getBytes(),
				null, Map.of("X-Forwarded-For", ip));
	}

	private static long retryAfter(Http.Response r) {
		return r.headers().firstValue("Retry-After").map(Long::parseLong).orElseThrow();
	}

	// ---- strict (email, IP) limiter ----

	@Test
	void fourthFailureIs429WithTheExactWaitAndTheBucketRefillsOnTheClock() {
		String email = uniqueEmail();
		newUser(email);
		for (int i = 0; i < 3; i++) {
			assertThat(login(email, "wrong password").status()).isEqualTo(401);
		}
		Http.Response limited = login(email, "wrong password");
		assertThat(limited.status()).isEqualTo(429);
		assertThat(limited.error()).isEqualTo("rate_limited");
		assertThat(retryAfter(limited)).isEqualTo(300);
		assertThat(login(email, "correct horse").status()).isEqualTo(429); // not locked, just waiting

		clock.advance(Duration.ofSeconds(299));
		Http.Response almost = login(email, "correct horse");
		assertThat(almost.status()).isEqualTo(429);
		assertThat(retryAfter(almost)).isEqualTo(1);

		clock.advance(Duration.ofSeconds(1));
		assertThat(login(email, "correct horse").status()).isEqualTo(200);
	}

	@Test
	void anAttackerIsBlockedOnlyFromTheirOwnIp() {
		String email = uniqueEmail();
		newUser(email);
		for (int i = 0; i < 3; i++) {
			assertThat(loginFrom("203.0.113.1", email, "wrong password").status()).isEqualTo(401);
		}
		Http.Response blocked = loginFrom("203.0.113.1", email, "wrong password");
		assertThat(blocked.status()).isEqualTo(429);
		assertThat(retryAfter(blocked)).isEqualTo(300);
		assertThat(loginFrom("203.0.113.1", email, "correct horse").status()).isEqualTo(429);
		// the real user, from another IP, is not affected
		assertThat(loginFrom("198.51.100.7", email, "correct horse").status()).isEqualTo(200);
	}

	@Test
	void successfulLoginsDoNotSpendTheFailureBudget() {
		String email = uniqueEmail();
		newUser(email);
		for (int i = 0; i < 8; i++) {
			assertThat(login(email, "correct horse").status()).isEqualTo(200);
		}
		for (int i = 0; i < 3; i++) {
			assertThat(login(email, "wrong password").status()).isEqualTo(401);
		}
		assertThat(login(email, "wrong password").status()).isEqualTo(429);
	}

	@Test
	void aSuccessIsNetZero() {
		String email = uniqueEmail();
		newUser(email);
		for (int i = 0; i < 2; i++) {
			assertThat(login(email, "wrong password").status()).isEqualTo(401);
		}
		assertThat(login(email, "correct horse").status()).isEqualTo(200); // one token left; spent and given back
		assertThat(login(email, "wrong password").status()).isEqualTo(401); // the 3rd failure still fits
		assertThat(login(email, "wrong password").status()).isEqualTo(429);
	}

	@Test
	void theLimitIsPerEmailAndIgnoresCase() {
		String a = uniqueEmail();
		for (int i = 0; i < 3; i++) {
			login(a.toUpperCase(), "whatever1");
		}
		assertThat(login(a, "whatever1").status()).isEqualTo(429); // same bucket as the upper-case spelling
		assertThat(login(uniqueEmail(), "whatever1").status()).isEqualTo(401); // somebody else is unaffected
	}

	@Test
	void signupAndRefreshAreNotCountedAgainstTheLoginBudget() {
		String email = uniqueEmail();
		for (int i = 0; i < 2; i++) {
			assertThat(login(email, "whatever1").status()).isEqualTo(401);
		}
		newUser(uniqueEmail());
		assertThat(login(email, "whatever1").status()).isEqualTo(401);
		assertThat(login(email, "whatever1").status()).isEqualTo(429);
	}

	@Test
	void unknownAndKnownEmailsBehaveIdentically() {
		String known = uniqueEmail();
		String unknown = uniqueEmail();
		newUser(known);
		Http.Response k401 = loginFrom("203.0.113.9", known, "wrong password");
		Http.Response u401 = loginFrom("203.0.113.9", unknown, "wrong password");
		assertThat(k401.status()).isEqualTo(401);
		assertThat(k401.body()).isEqualTo(u401.body());
		for (int i = 0; i < 2; i++) {
			loginFrom("203.0.113.9", known, "wrong password");
			loginFrom("203.0.113.9", unknown, "wrong password");
		}
		Http.Response k429 = loginFrom("203.0.113.9", known, "wrong password");
		Http.Response u429 = loginFrom("203.0.113.9", unknown, "wrong password");
		assertThat(k429.status()).isEqualTo(429);
		assertThat(u429.status()).isEqualTo(429);
		assertThat(k429.body()).isEqualTo(u429.body());
		assertThat(retryAfter(k429)).isEqualTo(retryAfter(u429)).isEqualTo(300);
		// the right password from another IP: the known user gets in, the unknown one is an ordinary 401
		assertThat(loginFrom("198.51.100.9", known, "correct horse").status()).isEqualTo(200);
		assertThat(loginFrom("198.51.100.9", unknown, "correct horse").status()).isEqualTo(401);
	}

	// ---- loose (email) limiter ----

	@Test
	void failuresSpreadOverManyIpsTripTheLooseLimit() {
		String email = uniqueEmail();
		newUser(email);
		// 3 IPs x 3 failures = 9: each one is allowed by the strict limiter
		for (int ip = 1; ip <= 3; ip++) {
			for (int i = 0; i < 3; i++) {
				assertThat(loginFrom("192.0.2." + ip, email, "wrong password").status()).isEqualTo(401);
			}
		}
		// a fresh IP: strict is full, loose is empty -> the loose wait, one token every 100 s
		Http.Response fresh = loginFrom("192.0.2.200", email, "wrong password");
		assertThat(fresh.status()).isEqualTo(429);
		assertThat(fresh.error()).isEqualTo("rate_limited");
		assertThat(retryAfter(fresh)).isEqualTo(100);
		// an IP that has also used up its strict budget: Retry-After is the longer of the two waits
		assertThat(retryAfter(loginFrom("192.0.2.3", email, "wrong password"))).isEqualTo(300);
		// the trade-off, stated plainly: now everyone is blocked for this email, even with the right password
		assertThat(loginFrom("192.0.2.201", email, "correct horse").status()).isEqualTo(429);
		// other emails are unaffected
		assertThat(loginFrom("192.0.2.200", uniqueEmail(), "whatever1").status()).isEqualTo(401);

		clock.advance(Duration.ofSeconds(100));
		assertThat(loginFrom("192.0.2.202", email, "correct horse").status()).isEqualTo(200);
	}

	@Test
	void aSuccessfulLoginRefundsBothLimiters() {
		String email = uniqueEmail();
		newUser(email);
		// leave the loose limiter with 3 tokens: 6 failures from 2 IPs
		for (int ip = 1; ip <= 2; ip++) {
			for (int i = 0; i < 3; i++) {
				assertThat(loginFrom("192.0.2." + ip, email, "wrong password").status()).isEqualTo(401);
			}
		}
		// many more successes than 3: each spends a token in both limiters and gives it back
		for (int i = 0; i < 8; i++) {
			assertThat(loginFrom("198.51.100." + (i % 2 + 1), email, "correct horse").status()).as("login %d", i).isEqualTo(200);
		}
		// the loose limiter still has exactly its 3: three more failures fit, the fourth does not
		for (int i = 0; i < 3; i++) {
			assertThat(loginFrom("203.0.113." + (100 + i), email, "wrong password").status()).isEqualTo(401);
		}
		assertThat(loginFrom("203.0.113.150", email, "wrong password").status()).isEqualTo(429);
	}
}
