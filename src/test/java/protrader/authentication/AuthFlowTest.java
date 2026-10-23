package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;
import tools.jackson.databind.JsonNode;

/** Signup, login, refresh, logout, /v1/me (tests 2, 3, 4 and 6 of the task). */
class AuthFlowTest extends IntegrationTest {

	private static String signupBody(String email, String password, String name) {
		return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\",\"display_name\":\"" + name + "\"}";
	}

	// ---- signup ----

	@Test
	void signupSucceedsWithAccountIdAsString() {
		Http.Response r = http().post("/v1/auth/signup", signupBody(uniqueEmail(), "correct horse", "Ann"));
		assertThat(r.status()).isEqualTo(201);
		assertThat(r.json().get("account_id").isString()).isTrue();
		assertThat(Long.parseLong(r.json().get("account_id").asString())).isGreaterThanOrEqualTo(1000);
		assertThat(r.json().size()).isEqualTo(1);
	}

	@Test
	void duplicateEmailIs409EvenWithOtherCaseAndWhitespace() {
		String email = uniqueEmail();
		assertThat(http().post("/v1/auth/signup", signupBody(email, "correct horse", "A")).status()).isEqualTo(201);
		Http.Response again = http().post("/v1/auth/signup", signupBody("  " + email.toUpperCase() + " ", "another pass", "B"));
		assertThat(again.status()).isEqualTo(409);
		assertThat(again.error()).isEqualTo("email_taken");
	}

	@Test
	void validationErrorsNameTheField() {
		String ok = uniqueEmail();
		assertField(signupBody("", "correct horse", "A"), "email");
		assertField(signupBody("no-at-sign", "correct horse", "A"), "email");
		assertField(signupBody("a@@b.com", "correct horse", "A"), "email");
		assertField(signupBody("@b.com", "correct horse", "A"), "email");
		assertField(signupBody("a@nodot", "correct horse", "A"), "email");
		assertField(signupBody("a".repeat(250) + "@b.com", "correct horse", "A"), "email");
		assertField(signupBody(ok, "short", "A"), "password");
		assertField(signupBody(ok, "x".repeat(73), "A"), "password");
		assertField(signupBody(ok, "é".repeat(37), "A"), "password"); // 74 bytes, 37 chars
		assertField(signupBody(ok, "correct horse", "   "), "display_name");
		assertField(signupBody(ok, "correct horse", "x".repeat(41)), "display_name");
		assertField(signupBody(ok, "correct horse", "bad\\u0007name"), "display_name");
		assertField("{\"email\":\"" + ok + "\",\"password\":\"correct horse\"}", "display_name");
	}

	@Test
	void passwordOf72BytesIsAccepted() {
		assertThat(http().post("/v1/auth/signup", signupBody(uniqueEmail(), "x".repeat(72), "A")).status()).isEqualTo(201);
	}

	private void assertField(String body, String field) {
		Http.Response r = http().post("/v1/auth/signup", body);
		assertThat(r.status()).as(body).isEqualTo(422);
		assertThat(r.error()).isEqualTo("invalid_field");
		assertThat(r.json().get("field").asString()).as(body).isEqualTo(field);
	}

	@Test
	void concurrentSignupsOfTheSameEmailCreateExactlyOneAccount() throws Exception {
		String email = uniqueEmail();
		ExecutorService pool = Executors.newFixedThreadPool(8);
		try {
			List<Callable<Integer>> jobs = new ArrayList<>();
			for (int i = 0; i < 8; i++) {
				jobs.add(() -> http().post("/v1/auth/signup", signupBody(email, "correct horse", "A")).status());
			}
			int created = 0;
			int conflicts = 0;
			for (Future<Integer> f : pool.invokeAll(jobs)) {
				int status = f.get();
				if (status == 201) {
					created++;
				} else if (status == 409) {
					conflicts++;
				}
			}
			assertThat(created).isEqualTo(1);
			assertThat(conflicts).isEqualTo(7);
		} finally {
			pool.shutdownNow();
		}
	}

	// ---- login ----

	@Test
	void loginReturnsTokensInTheContractShape() {
		String email = uniqueEmail();
		JsonNode login = newUser(email);
		assertThat(login.propertyNames()).containsExactlyInAnyOrder("access_token", "token_type", "expires_in", "refresh_token", "account_id");
		assertThat(login.get("token_type").asString()).isEqualTo("Bearer");
		assertThat(login.get("expires_in").asInt()).isEqualTo(3600);
		assertThat(login.get("refresh_token").asString().length()).isGreaterThanOrEqualTo(43);
		assertThat(login.get("account_id").isString()).isTrue();
	}

	@Test
	void wrongPasswordAndUnknownEmailGiveIdenticalBodies() {
		String email = uniqueEmail();
		newUser(email);
		Http.Response wrongPassword = http().post("/v1/auth/login", "{\"email\":\"" + email + "\",\"password\":\"wrong password\"}");
		Http.Response unknownEmail = http().post("/v1/auth/login", "{\"email\":\"" + uniqueEmail() + "\",\"password\":\"wrong password\"}");
		assertThat(wrongPassword.status()).isEqualTo(401);
		assertThat(unknownEmail.status()).isEqualTo(401);
		assertThat(wrongPassword.body()).isEqualTo(unknownEmail.body());
		assertThat(wrongPassword.error()).isEqualTo("bad_credentials");
	}

	@Test
	void loginAcceptsEmailInAnyCase() {
		String email = uniqueEmail();
		newUser(email);
		Http.Response r = http().post("/v1/auth/login", "{\"email\":\" " + email.toUpperCase() + "\",\"password\":\"correct horse\"}");
		assertThat(r.status()).isEqualTo(200);
	}

	@Test
	void passwordLoginOnAGoogleOnlyAccountIsRejected() {
		String email = uniqueEmail();
		google.register("g-only-" + email, new protrader.authentication.google.GoogleIdentity("sub-" + email, email, "G"));
		assertThat(http().post("/v1/auth/google", "{\"id_token\":\"g-only-" + email + "\"}").status()).isEqualTo(200);
		Http.Response r = http().post("/v1/auth/login", "{\"email\":\"" + email + "\",\"password\":\"anything at all\"}");
		assertThat(r.status()).isEqualTo(401);
		assertThat(r.error()).isEqualTo("bad_credentials");
	}

	// ---- refresh / logout ----

	@Test
	void refreshRotatesAndReturnsTheLoginShape() {
		JsonNode login = newUser(uniqueEmail());
		Http.Response r = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + login.get("refresh_token").asString() + "\"}");
		assertThat(r.status()).isEqualTo(200);
		JsonNode next = r.json();
		assertThat(next.propertyNames()).containsExactlyInAnyOrder("access_token", "token_type", "expires_in", "refresh_token", "account_id");
		assertThat(next.get("refresh_token").asString()).isNotEqualTo(login.get("refresh_token").asString());
		assertThat(next.get("account_id").asString()).isEqualTo(login.get("account_id").asString());
		// the new pair works
		assertThat(http().get("/v1/me", next.get("access_token").asString()).status()).isEqualTo(200);
		assertThat(http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + next.get("refresh_token").asString() + "\"}").status()).isEqualTo(200);
	}

	@Test
	void reusingAnOldRefreshTokenRevokesTheWholeFamily() {
		JsonNode login = newUser(uniqueEmail());
		String first = login.get("refresh_token").asString();
		Http.Response rotated = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + first + "\"}");
		String second = rotated.json().get("refresh_token").asString();

		Http.Response replay = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + first + "\"}");
		assertThat(replay.status()).isEqualTo(401);
		assertThat(replay.error()).isEqualTo("bad_refresh_token");

		Http.Response afterReplay = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + second + "\"}");
		assertThat(afterReplay.status()).isEqualTo(401);
		assertThat(afterReplay.error()).isEqualTo("bad_refresh_token");
	}

	@Test
	void unknownAndExpiredRefreshTokensAreTheSame401() {
		JsonNode login = newUser(uniqueEmail());
		String token = login.get("refresh_token").asString();
		Http.Response unknown = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + "A".repeat(43) + "\"}");

		jdbc.sql("UPDATE refresh_tokens SET expires_at = now() - interval '1 minute' WHERE account_id = ?")
				.param(Long.parseLong(login.get("account_id").asString())).update();
		Http.Response expired = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + token + "\"}");

		assertThat(unknown.status()).isEqualTo(401);
		assertThat(expired.status()).isEqualTo(401);
		assertThat(expired.body()).isEqualTo(unknown.body());
		assertThat(expired.error()).isEqualTo("bad_refresh_token");
	}

	@Test
	void familyLifetimeCapEndsTheChainEvenForActiveUsers() {
		JsonNode login = newUser(uniqueEmail());
		jdbc.sql("UPDATE refresh_tokens SET family_expires_at = now() - interval '1 minute' WHERE account_id = ?")
				.param(Long.parseLong(login.get("account_id").asString())).update();
		Http.Response r = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + login.get("refresh_token").asString() + "\"}");
		assertThat(r.status()).isEqualTo(401);
	}

	@Test
	void rotatedTokenNeverOutlivesTheFamilyCap() {
		JsonNode login = newUser(uniqueEmail());
		long account = Long.parseLong(login.get("account_id").asString());
		jdbc.sql("UPDATE refresh_tokens SET family_expires_at = now() + interval '2 days', expires_at = now() + interval '1 day' WHERE account_id = ?").param(account).update();
		assertThat(http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + login.get("refresh_token").asString() + "\"}").status()).isEqualTo(200);
		Boolean capped = jdbc.sql("SELECT bool_and(expires_at <= family_expires_at) FROM refresh_tokens WHERE account_id = ?")
				.param(account).query(Boolean.class).single();
		assertThat(capped).isTrue();
	}

	@Test
	void logoutRevokesTheFamilyAndIsRepeatable() {
		JsonNode login = newUser(uniqueEmail());
		String token = login.get("refresh_token").asString();
		String body = "{\"refresh_token\":\"" + token + "\"}";
		assertThat(http().post("/v1/auth/logout", body).status()).isEqualTo(204);
		assertThat(http().post("/v1/auth/logout", body).status()).isEqualTo(204);
		assertThat(http().post("/v1/auth/refresh", body).status()).isEqualTo(401);
		assertThat(http().post("/v1/auth/logout", "{\"refresh_token\":\"never-issued\"}").status()).isEqualTo(204);
		assertThat(http().post("/v1/auth/logout", "{}").status()).isEqualTo(204);
	}

	@Test
	void concurrentRefreshWithOneTokenSucceedsAtMostOnce() throws Exception {
		JsonNode login = newUser(uniqueEmail());
		String body = "{\"refresh_token\":\"" + login.get("refresh_token").asString() + "\"}";
		ExecutorService pool = Executors.newFixedThreadPool(6);
		try {
			List<Callable<Integer>> jobs = new ArrayList<>();
			for (int i = 0; i < 6; i++) {
				jobs.add(() -> http().post("/v1/auth/refresh", body).status());
			}
			int ok = 0;
			for (Future<Integer> f : pool.invokeAll(jobs)) {
				int status = f.get();
				assertThat(status).isIn(200, 401);
				if (status == 200) {
					ok++;
				}
			}
			assertThat(ok).isLessThanOrEqualTo(1);
		} finally {
			pool.shutdownNow();
		}
	}

	// ---- /v1/me ----

	@Test
	void meReturnsTheAccount() {
		String email = uniqueEmail();
		JsonNode login = newUser(email);
		Http.Response r = http().get("/v1/me", login.get("access_token").asString());
		assertThat(r.status()).isEqualTo(200);
		assertThat(r.json().propertyNames()).containsExactlyInAnyOrder("account_id", "email", "display_name", "created_at");
		assertThat(r.json().get("account_id").asString()).isEqualTo(login.get("account_id").asString());
		assertThat(r.json().get("email").asString()).isEqualTo(email);
		assertThat(r.json().get("display_name").asString()).isEqualTo("Tester");
		assertThat(r.json().get("created_at").asString()).matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z");
	}
}
