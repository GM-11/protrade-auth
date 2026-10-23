package protrader.authentication.google;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import protrader.authentication.token.Hashes;

/**
 * Server-issued nonces for the id_token shape. A client-chosen nonce proves nothing about freshness;
 * one the server issued, and burns on first use, stops a stolen ID token from being replayed.
 */
@Service
public class GoogleNonceService {

	public static final Duration TTL = Duration.ofMinutes(5);

	private static final Logger log = LoggerFactory.getLogger(GoogleNonceService.class);
	private static final SecureRandom RANDOM = new SecureRandom();

	private final JdbcClient jdbc;
	private final Clock clock;

	public GoogleNonceService(JdbcClient jdbc, Clock clock) {
		this.jdbc = jdbc;
		this.clock = clock;
	}

	/** A fresh nonce; only its SHA-256 is stored. */
	public String issue() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		jdbc.sql("INSERT INTO google_nonces (nonce_sha256, expires_at) VALUES (?, ?)")
				.params(Hashes.sha256(nonce), now().plus(TTL))
				.update();
		return nonce;
	}

	/** Atomically burns the nonce. False when it is unknown, expired or already used. */
	public boolean consume(String nonce) {
		return jdbc.sql("DELETE FROM google_nonces WHERE nonce_sha256 = ? AND expires_at > ? RETURNING 1")
				.params(Hashes.sha256(nonce), now())
				.query(Integer.class)
				.optional()
				.isPresent();
	}

	@Scheduled(cron = "0 */10 * * * *")
	public void purgeExpired() {
		int deleted = jdbc.sql("DELETE FROM google_nonces WHERE expires_at < ?").param(now()).update();
		log.debug("purged {} expired Google nonces", deleted);
	}

	private OffsetDateTime now() {
		return OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
	}
}
