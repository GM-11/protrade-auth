package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;
import tools.jackson.databind.JsonNode;

/** Refresh reuse detection with the 10 s grace window (REFRESH_REUSE_GRACE). */
class RefreshGraceTest extends IntegrationTest {

	private Http.Response refresh(String token) {
		return http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + token + "\"}");
	}

	/** Pretends the token was rotated this many seconds ago. */
	private void ageUsedToken(String token, int seconds) {
		jdbc.sql("UPDATE refresh_tokens SET used_at = now() - make_interval(secs => ?) WHERE token_sha256 = sha256(convert_to(?, 'UTF8'))")
				.params(seconds, token).update();
	}

	@Test
	void retryWithinTheWindowGetsASiblingAndTheFamilyStaysAlive() {
		JsonNode login = newUser(uniqueEmail());
		String first = login.get("refresh_token").asString();
		Http.Response winner = refresh(first);
		assertThat(winner.status()).isEqualTo(200);

		ageUsedToken(first, 5); // the response was lost; the client retries 5 s later
		Http.Response retry = refresh(first);
		assertThat(retry.status()).isEqualTo(200);
		assertThat(retry.json().propertyNames()).containsExactlyInAnyOrder("access_token", "token_type", "expires_in", "refresh_token", "account_id");
		String sibling = retry.json().get("refresh_token").asString();
		assertThat(sibling).isNotEqualTo(winner.json().get("refresh_token").asString()).isNotEqualTo(first);

		// both descendants are alive, and so is the family
		assertThat(refresh(sibling).status()).isEqualTo(200);
		assertThat(refresh(winner.json().get("refresh_token").asString()).status()).isEqualTo(200);
	}

	@Test
	void replayAfterTheWindowRevokesTheWholeFamily() {
		JsonNode login = newUser(uniqueEmail());
		String first = login.get("refresh_token").asString();
		String second = refresh(first).json().get("refresh_token").asString();

		ageUsedToken(first, 15);
		Http.Response replay = refresh(first);
		assertThat(replay.status()).isEqualTo(401);
		assertThat(replay.error()).isEqualTo("bad_refresh_token");
		assertThat(refresh(second).status()).isEqualTo(401); // the family is dead
	}

	@Test
	void aRevokedFamilyIsNotRevivedByTheWindow() {
		JsonNode login = newUser(uniqueEmail());
		String first = login.get("refresh_token").asString();
		refresh(first);
		assertThat(http().post("/v1/auth/logout", "{\"refresh_token\":\"" + first + "\"}").status()).isEqualTo(204);
		assertThat(refresh(first).status()).isEqualTo(401); // used a moment ago, but revoked
	}

	@Test
	void twoConcurrentRefreshesWithOneTokenBothSucceed() throws Exception {
		JsonNode login = newUser(uniqueEmail());
		String token = login.get("refresh_token").asString();
		ExecutorService pool = Executors.newFixedThreadPool(2);
		try {
			CountDownLatch go = new CountDownLatch(1);
			Callable<Http.Response> job = () -> {
				go.await();
				return refresh(token);
			};
			List<Future<Http.Response>> futures = List.of(pool.submit(job), pool.submit(job));
			go.countDown();
			Http.Response a = futures.get(0).get();
			Http.Response b = futures.get(1).get();
			assertThat(a.status()).isEqualTo(200);
			assertThat(b.status()).isEqualTo(200);
			assertThat(a.json().get("refresh_token").asString()).isNotEqualTo(b.json().get("refresh_token").asString());
			// and the winner's token was not killed by the loser
			assertThat(refresh(a.json().get("refresh_token").asString()).status()).isEqualTo(200);
			assertThat(refresh(b.json().get("refresh_token").asString()).status()).isEqualTo(200);
		} finally {
			pool.shutdownNow();
		}
	}
}
