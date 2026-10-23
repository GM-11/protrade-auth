package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;

import protrader.authentication.google.GoogleIdentity;
import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;
import tools.jackson.databind.JsonNode;

/** Test 5: POST /v1/auth/google with Google stubbed behind its two interfaces. */
class GoogleFlowTest extends IntegrationTest {

	private static final String REDIRECT = "https://app.example.com/auth/callback";
	private static final String VERIFIER = "v".repeat(43);

	private String sub() {
		return "sub-" + UUID.randomUUID();
	}

	private Http.Response googleIdToken(String token) {
		return googleIdTokenLogin(token);
	}

	@Test
	void validIdTokenCreatesAnAccountAndSameSubReturnsTheSameOne() {
		String email = uniqueEmail();
		String sub = sub();
		google.register("tok-" + sub, new GoogleIdentity(sub, email, "Gina Google"));

		Http.Response first = googleIdToken("tok-" + sub);
		assertThat(first.status()).isEqualTo(200);
		assertThat(first.json().propertyNames()).containsExactlyInAnyOrder("access_token", "token_type", "expires_in", "refresh_token", "account_id");
		Http.Response me = http().get("/v1/me", first.json().get("access_token").asString());
		assertThat(me.json().get("email").asString()).isEqualTo(email);
		assertThat(me.json().get("display_name").asString()).isEqualTo("Gina Google");

		Http.Response second = googleIdToken("tok-" + sub);
		assertThat(second.status()).isEqualTo(200);
		assertThat(second.json().get("account_id").asString()).isEqualTo(first.json().get("account_id").asString());
	}

	@Test
	void sameSubWithAChangedEmailStillFindsTheAccount() {
		String sub = sub();
		google.register("a-" + sub, new GoogleIdentity(sub, uniqueEmail(), "A"));
		google.register("b-" + sub, new GoogleIdentity(sub, uniqueEmail(), "A"));
		String id1 = googleIdToken("a-" + sub).json().get("account_id").asString();
		String id2 = googleIdToken("b-" + sub).json().get("account_id").asString();
		assertThat(id2).isEqualTo(id1);
	}

	@Test
	void displayNameFallsBackToTheEmailLocalPart() {
		String sub = sub();
		google.register("n-" + sub, new GoogleIdentity(sub, "fallback.person@example.com", null));
		Http.Response r = googleIdToken("n-" + sub);
		assertThat(http().get("/v1/me", r.json().get("access_token").asString()).json().get("display_name").asString()).isEqualTo("fallback.person");
	}

	@Test
	void codeShapeExchangesOnOurServerAndCreatesTheAccount() {
		String sub = sub();
		google.registerCode("code-" + sub, "tok-" + sub);
		google.register("tok-" + sub, new GoogleIdentity(sub, uniqueEmail(), "Code User"));
		Http.Response r = http().post("/v1/auth/google",
				"{\"code\":\"code-" + sub + "\",\"code_verifier\":\"" + VERIFIER + "\",\"redirect_uri\":\"" + REDIRECT + "\"}");
		assertThat(r.status()).isEqualTo(200);
		assertThat(google.exchanges).anySatisfy(c -> {
			assertThat(c.code()).isEqualTo("code-" + sub);
			assertThat(c.verifier()).isEqualTo(VERIFIER);
			assertThat(c.redirectUri()).isEqualTo(REDIRECT);
		});
	}

	@Test
	void existingPasswordAccountIsLinkedAndItsPasswordAndSessionsDie() {
		// the squatter scenario: someone registers victim@gmail.com with a password they know
		String email = uniqueEmail();
		JsonNode squatter = newUser(email);
		String squatterAccess = squatter.get("access_token").asString();
		assertThat(http().get("/v1/me", squatterAccess).status()).isEqualTo(200);

		// the real owner signs in with Google
		String sub = sub();
		google.register("victim-" + sub, new GoogleIdentity(sub, email, "Victim"));
		Http.Response victim = googleIdToken("victim-" + sub);
		assertThat(victim.status()).isEqualTo(200);
		assertThat(victim.json().get("account_id").asString()).isEqualTo(squatter.get("account_id").asString());

		// the squatter's password no longer works, and neither does their refresh token
		Http.Response password = http().post("/v1/auth/login", "{\"email\":\"" + email + "\",\"password\":\"correct horse\"}");
		assertThat(password.status()).isEqualTo(401);
		assertThat(password.error()).isEqualTo("bad_credentials");
		Http.Response refresh = http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + squatter.get("refresh_token").asString() + "\"}");
		assertThat(refresh.status()).isEqualTo(401);
		// the owner's own new session is fine
		assertThat(http().post("/v1/auth/refresh", "{\"refresh_token\":\"" + victim.json().get("refresh_token").asString() + "\"}").status()).isEqualTo(200);
		// and a later Google login finds the account by sub
		assertThat(googleIdToken("victim-" + sub).json().get("account_id").asString()).isEqualTo(squatter.get("account_id").asString());
	}

	@Test
	void anotherGoogleIdentityWithAnAlreadyLinkedEmailIsRefused() {
		String email = uniqueEmail();
		String sub1 = sub();
		google.register("one-" + sub1, new GoogleIdentity(sub1, email, "One"));
		assertThat(googleIdToken("one-" + sub1).status()).isEqualTo(200);

		String sub2 = sub();
		google.register("two-" + sub2, new GoogleIdentity(sub2, email, "Two"));
		Http.Response r = googleIdToken("two-" + sub2);
		assertThat(r.status()).isEqualTo(401);
		assertThat(r.error()).isEqualTo("bad_credentials");
	}

	@Test
	void rejectedTokenIs401WithoutSayingWhy() {
		Http.Response r = googleIdToken("not-registered");
		assertThat(r.status()).isEqualTo(401);
		assertThat(r.error()).isEqualTo("bad_credentials");
		Http.Response badCode = http().post("/v1/auth/google",
				"{\"code\":\"unknown\",\"code_verifier\":\"" + VERIFIER + "\",\"redirect_uri\":\"" + REDIRECT + "\"}");
		assertThat(badCode.status()).isEqualTo(401);
		assertThat(badCode.body()).isEqualTo(r.body());
	}

	@Test
	void googleBeingDownIs503() {
		google.down = true;
		try {
			Http.Response r = http().post("/v1/auth/google",
					"{\"code\":\"c\",\"code_verifier\":\"" + VERIFIER + "\",\"redirect_uri\":\"" + REDIRECT + "\"}");
			assertThat(r.status()).isEqualTo(503);
			assertThat(r.error()).isEqualTo("google_unavailable");
		} finally {
			google.down = false;
		}
	}

	@Test
	void requestShapeErrorsAre422WithTheField() {
		assertField("{}", "code");
		assertField("{\"code\":\"c\",\"code_verifier\":\"" + VERIFIER + "\",\"redirect_uri\":\"" + REDIRECT + "\",\"id_token\":\"t\"}", "id_token");
		assertField("{\"code\":\"c\",\"redirect_uri\":\"" + REDIRECT + "\"}", "code_verifier");
		assertField("{\"code\":\"c\",\"code_verifier\":\"short\",\"redirect_uri\":\"" + REDIRECT + "\"}", "code_verifier");
		assertField("{\"code\":\"c\",\"code_verifier\":\"" + VERIFIER + "\"}", "redirect_uri");
		// exact match only: no prefix, no extra path, no trailing slash
		assertField("{\"code\":\"c\",\"code_verifier\":\"" + VERIFIER + "\",\"redirect_uri\":\"" + REDIRECT + "/x\"}", "redirect_uri");
		assertField("{\"code\":\"c\",\"code_verifier\":\"" + VERIFIER + "\",\"redirect_uri\":\"https://evil.example.com/\"}", "redirect_uri");
		assertField("{\"id_token\":\"\",\"nonce\":\"n\"}", "id_token");
		assertField("{\"id_token\":\"t\"}", "nonce");
		assertField("{\"id_token\":\"t\",\"nonce\":\"\"}", "nonce");
		assertField("{\"nonce\":\"n\"}", "id_token");
	}

	private void assertField(String body, String field) {
		Http.Response r = http().post("/v1/auth/google", body);
		assertThat(r.status()).as(body).isEqualTo(422);
		assertThat(r.error()).isEqualTo("invalid_field");
		assertThat(r.json().get("field").asString()).as(body).isEqualTo(field);
	}

	@Test
	void twoFirstTimeLoginsAtOnceCreateOneAccount() throws Exception {
		String sub = sub();
		google.register("race-" + sub, new GoogleIdentity(sub, uniqueEmail(), "Racer"));
		ExecutorService pool = Executors.newFixedThreadPool(6);
		try {
			List<Callable<Http.Response>> jobs = new ArrayList<>();
			for (int i = 0; i < 6; i++) {
				jobs.add(() -> googleIdToken("race-" + sub));
			}
			List<String> ids = new ArrayList<>();
			for (Future<Http.Response> f : pool.invokeAll(jobs)) {
				Http.Response r = f.get();
				assertThat(r.status()).isEqualTo(200);
				ids.add(r.json().get("account_id").asString());
			}
			assertThat(ids).allMatch(id -> id.equals(ids.get(0)));
			Integer rows = jdbc.sql("SELECT count(*) FROM accounts WHERE google_sub = ?").param(sub).query(Integer.class).single();
			assertThat(rows).isEqualTo(1);
		} finally {
			pool.shutdownNow();
		}
	}
}
