package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;

/** Login-only limit: 5 failures per email per 15 minutes, never a lockout. */
@TestPropertySource(properties = {"auth.rate-limit.login-failures-per-email=5", "auth.internal-port=0"})
class LoginEmailLimitTest extends IntegrationTest {

	private Http.Response login(String email, String password) {
		return http().post("/v1/auth/login", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}");
	}

	@Test
	void sixthFailureIs429EvenWithTheRightPasswordUntilTheBucketRefills() {
		String email = uniqueEmail();
		newUser(email); // the signup + login here do not count as failures
		for (int i = 0; i < 5; i++) {
			assertThat(login(email, "wrong password").status()).isEqualTo(401);
		}
		Http.Response limited = login(email, "wrong password");
		assertThat(limited.status()).isEqualTo(429);
		assertThat(limited.error()).isEqualTo("rate_limited");
		// 15 min / 5 = one token per 3 minutes
		assertThat(limited.headers().firstValue("Retry-After").map(Long::parseLong).orElseThrow()).isBetween(1L, 180L);
		assertThat(login(email, "correct horse").status()).isEqualTo(429); // not locked, just waiting
	}

	@Test
	void successfulLoginsDoNotSpendTheFailureBudget() {
		String email = uniqueEmail();
		newUser(email);
		for (int i = 0; i < 30; i++) {
			assertThat(login(email, "correct horse").status()).isEqualTo(200);
		}
		// the full budget is still there
		for (int i = 0; i < 5; i++) {
			assertThat(login(email, "wrong password").status()).isEqualTo(401);
		}
		assertThat(login(email, "wrong password").status()).isEqualTo(429);
	}

	@Test
	void aSuccessIsNetZero() {
		String email = uniqueEmail();
		newUser(email);
		for (int i = 0; i < 4; i++) {
			assertThat(login(email, "wrong password").status()).isEqualTo(401);
		}
		assertThat(login(email, "correct horse").status()).isEqualTo(200); // one token left; spent and given back
		assertThat(login(email, "wrong password").status()).isEqualTo(401); // the 5th failure still fits
		assertThat(login(email, "wrong password").status()).isEqualTo(429);
	}

	@Test
	void unknownEmailsAreLimitedTheSameWay() {
		String email = uniqueEmail();
		for (int i = 0; i < 5; i++) {
			assertThat(login(email, "whatever1").status()).isEqualTo(401);
		}
		assertThat(login(email, "whatever1").status()).isEqualTo(429);
	}

	@Test
	void theLimitIsPerEmailNotGlobalAndIgnoresCase() {
		String a = uniqueEmail();
		for (int i = 0; i < 5; i++) {
			login(a.toUpperCase(), "whatever1");
		}
		assertThat(login(a, "whatever1").status()).isEqualTo(429); // same bucket as the upper-case spelling
		assertThat(login(uniqueEmail(), "whatever1").status()).isEqualTo(401); // somebody else is unaffected
	}

	@Test
	void signupAndRefreshAreNotCountedAgainstTheLoginBudget() {
		String email = uniqueEmail();
		for (int i = 0; i < 3; i++) {
			assertThat(login(email, "whatever1").status()).isEqualTo(401);
		}
		newUser(uniqueEmail());
		assertThat(login(email, "whatever1").status()).isEqualTo(401);
		assertThat(login(email, "whatever1").status()).isEqualTo(401);
		assertThat(login(email, "whatever1").status()).isEqualTo(429);
	}
}
