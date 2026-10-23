package protrader.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import protrader.authentication.google.GoogleIdentity;
import protrader.authentication.google.GoogleNonceService;
import protrader.authentication.support.Http;
import protrader.authentication.support.IntegrationTest;

/** Server-issued, single-use nonces for the id_token shape of POST /v1/auth/google. */
class GoogleNonceTest extends IntegrationTest {

	@Autowired
	GoogleNonceService nonceService;

	private String registerToken(String nonceClaim) {
		String id = UUID.randomUUID().toString();
		String token = "tok-" + id;
		GoogleIdentity identity = new GoogleIdentity("sub-" + id, uniqueEmail(), "Nonce User");
		if (nonceClaim == null) {
			google.register(token, identity);
		} else {
			google.register(token, identity, nonceClaim);
		}
		return token;
	}

	private Http.Response signIn(String token, String nonce) {
		return http().post("/v1/auth/google", "{\"id_token\":\"" + token + "\",\"nonce\":\"" + nonce + "\"}");
	}

	private static byte[] sha256(String s) throws Exception {
		return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
	}

	@Test
	void nonceEndpointNeedsNoAuthAndStoresOnlyTheHash() throws Exception {
		Http.Response r = http().post("/v1/auth/google/nonce", "");
		assertThat(r.status()).isEqualTo(200);
		assertThat(r.json().propertyNames()).containsExactlyInAnyOrder("nonce", "expires_in");
		assertThat(r.json().get("expires_in").asInt()).isEqualTo(300);
		String nonce = r.json().get("nonce").asString();
		assertThat(nonce).matches("[A-Za-z0-9_-]{43}"); // 32 random bytes, base64url

		Integer rows = jdbc.sql("SELECT count(*) FROM google_nonces WHERE nonce_sha256 = ?").param(sha256(nonce)).query(Integer.class).single();
		assertThat(rows).isEqualTo(1);
		assertThat(http().post("/v1/auth/google/nonce", "").json().get("nonce").asString()).isNotEqualTo(nonce);
	}

	@Test
	void aNonceWorksExactlyOnce() {
		String nonce = newNonce();
		String token = registerToken(nonce);
		assertThat(signIn(token, nonce).status()).isEqualTo(200);
		Http.Response again = signIn(token, nonce);
		assertThat(again.status()).isEqualTo(401);
		assertThat(again.error()).isEqualTo("bad_credentials");
	}

	@Test
	void anExpiredNonceIsRejected() throws Exception {
		String nonce = newNonce();
		jdbc.sql("UPDATE google_nonces SET expires_at = now() - interval '1 second' WHERE nonce_sha256 = ?").param(sha256(nonce)).update();
		Http.Response r = signIn(registerToken(nonce), nonce);
		assertThat(r.status()).isEqualTo(401);
		assertThat(r.error()).isEqualTo("bad_credentials");
	}

	@Test
	void aMadeUpNonceIsRejected() {
		String made = "A".repeat(43);
		Http.Response r = signIn(registerToken(made), made);
		assertThat(r.status()).isEqualTo(401);
		assertThat(r.body()).isEqualTo(signIn("unknown-token", newNonce()).body()); // same answer as any other rejection
	}

	@Test
	void aTokenWhoseNonceClaimDiffersFromTheRequestsIsRejected() {
		String nonce = newNonce();
		String token = registerToken("some-other-nonce");
		Http.Response r = signIn(token, nonce);
		assertThat(r.status()).isEqualTo(401);
		assertThat(r.error()).isEqualTo("bad_credentials");
	}

	@Test
	void theNonceIsBurnedBeforeTheTokenIsChecked() throws Exception {
		String nonce = newNonce();
		assertThat(signIn("garbage-token", nonce).status()).isEqualTo(401);
		Integer left = jdbc.sql("SELECT count(*) FROM google_nonces WHERE nonce_sha256 = ?").param(sha256(nonce)).query(Integer.class).single();
		assertThat(left).isZero();
	}

	@Test
	void missingNonceIs422() {
		Http.Response r = http().post("/v1/auth/google", "{\"id_token\":\"" + registerToken(null) + "\"}");
		assertThat(r.status()).isEqualTo(422);
		assertThat(r.error()).isEqualTo("invalid_field");
		assertThat(r.json().get("field").asString()).isEqualTo("nonce");
	}

	@Test
	void concurrentRequestsWithOneNonceSucceedAtMostOnce() throws Exception {
		String nonce = newNonce();
		int n = 6;
		ExecutorService pool = Executors.newFixedThreadPool(n);
		try {
			CountDownLatch go = new CountDownLatch(1);
			List<Callable<Integer>> jobs = new ArrayList<>();
			for (int i = 0; i < n; i++) {
				String token = registerToken(nonce);
				jobs.add(() -> {
					go.await();
					return signIn(token, nonce).status();
				});
			}
			List<Future<Integer>> futures = jobs.stream().map(pool::submit).toList();
			go.countDown();
			int ok = 0;
			for (Future<Integer> f : futures) {
				int status = f.get();
				assertThat(status).isIn(200, 401);
				if (status == 200) {
					ok++;
				}
			}
			assertThat(ok).isEqualTo(1);
		} finally {
			pool.shutdownNow();
		}
	}

	@Test
	void purgeRemovesExpiredRowsOnly() throws Exception {
		String dead = newNonce();
		String alive = newNonce();
		jdbc.sql("UPDATE google_nonces SET expires_at = now() - interval '1 minute' WHERE nonce_sha256 = ?").param(sha256(dead)).update();
		nonceService.purgeExpired();
		assertThat(jdbc.sql("SELECT count(*) FROM google_nonces WHERE nonce_sha256 = ?").param(sha256(dead)).query(Integer.class).single()).isZero();
		assertThat(jdbc.sql("SELECT count(*) FROM google_nonces WHERE nonce_sha256 = ?").param(sha256(alive)).query(Integer.class).single()).isEqualTo(1);
	}

	@Test
	void theCodeShapeNeedsNoNonce() {
		String id = UUID.randomUUID().toString();
		google.registerCode("code-" + id, "tok-" + id);
		google.register("tok-" + id, new GoogleIdentity("sub-" + id, uniqueEmail(), "Code"));
		Http.Response r = http().post("/v1/auth/google", "{\"code\":\"code-" + id + "\",\"code_verifier\":\"" + "v".repeat(43)
				+ "\",\"redirect_uri\":\"https://app.example.com/auth/callback\"}");
		assertThat(r.status()).isEqualTo(200);
	}
}
