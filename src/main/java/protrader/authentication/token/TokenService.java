package protrader.authentication.token;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import protrader.authentication.config.AuthProperties;
import protrader.authentication.web.ApiException;

/** Issues access + refresh tokens and runs the refresh-token family rules. */
@Service
public class TokenService {

	private static final Logger log = LoggerFactory.getLogger(TokenService.class);
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final Duration KEEP_AFTER_EXPIRY = Duration.ofDays(7);

	private final JwtSigner signer;
	private final RefreshTokenRepository refreshTokens;
	private final TransactionTemplate tx;
	private final Clock clock;
	private final Duration accessTtl;
	private final Duration refreshTtl;
	private final Duration familyMaxTtl;
	private final Duration reuseGrace;

	public TokenService(JwtSigner signer, RefreshTokenRepository refreshTokens, TransactionTemplate tx, Clock clock, AuthProperties props) {
		this.signer = signer;
		this.refreshTokens = refreshTokens;
		this.tx = tx;
		this.clock = clock;
		this.accessTtl = props.accessTokenTtl();
		this.refreshTtl = props.refreshTokenTtl();
		this.familyMaxTtl = props.refreshFamilyMaxTtl();
		this.reuseGrace = props.refreshReuseGrace();
	}

	/** A fresh login: new refresh-token family. */
	public LoginResponse login(long accountId) {
		OffsetDateTime now = now();
		String refresh = newRefreshToken();
		refreshTokens.insert(accountId, UUID.randomUUID(), Hashes.sha256(refresh), now,
				now.plus(refreshTtl), now.plus(familyMaxTtl));
		return response(accountId, refresh);
	}

	/**
	 * Rotates a refresh token. A token already rotated within {@code REFRESH_REUSE_GRACE} is treated as
	 * a retry after a lost response (or the loser of a concurrent refresh): it gets a fresh sibling
	 * token in the same family and nothing is revoked. Replayed after the window, it is a stolen copy:
	 * the whole family is revoked.
	 */
	public LoginResponse refresh(String token) {
		byte[] hash = Hashes.sha256(token);
		Optional<LoginResponse> rotated = tx.execute(status -> {
			OffsetDateTime now = now();
			Optional<RefreshTokenRepository.Rotated> used = refreshTokens.markUsed(hash, now);
			if (used.isPresent()) {
				RefreshTokenRepository.Rotated r = used.get();
				return Optional.of(issueInFamily(r.accountId(), r.familyId(), r.familyExpiresAt(), now));
			}
			Optional<RefreshTokenRepository.Row> row = refreshTokens.find(hash);
			if (row.isEmpty() || !row.get().used()) {
				return Optional.empty(); // unknown, expired or revoked: plain no
			}
			RefreshTokenRepository.Row r = row.get();
			boolean withinGrace = !r.revoked()
					&& !r.usedAt().plus(reuseGrace).isBefore(now)
					&& r.expiresAt().isAfter(now)
					&& r.familyExpiresAt().isAfter(now);
			if (withinGrace) {
				return Optional.of(issueInFamily(r.accountId(), r.familyId(), r.familyExpiresAt(), now));
			}
			refreshTokens.revokeFamily(r.familyId(), now);
			return Optional.empty();
		});
		// a revoke above is committed; only now do we say no
		return rotated.orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED,
				"bad_refresh_token", "invalid refresh token"));
	}

	private LoginResponse issueInFamily(long accountId, UUID familyId, OffsetDateTime familyExpiresAt, OffsetDateTime now) {
		String next = newRefreshToken();
		OffsetDateTime expires = min(now.plus(refreshTtl), familyExpiresAt);
		refreshTokens.insert(accountId, familyId, Hashes.sha256(next), now, expires, familyExpiresAt);
		return response(accountId, next);
	}

	/** Revokes the token's whole family. Silent when the token is unknown, so it is safe to repeat. */
	public void logout(String token) {
		if (token == null || token.isEmpty()) {
			return;
		}
		byte[] hash = Hashes.sha256(token);
		refreshTokens.find(hash).ifPresent(row -> refreshTokens.revokeFamily(row.familyId(), now()));
	}

	public void revokeAll(long accountId) {
		refreshTokens.revokeAllForAccount(accountId, now());
	}

	@Scheduled(cron = "0 17 3 * * *")
	public void purgeExpired() {
		int deleted = refreshTokens.deleteExpiredBefore(now().minus(KEEP_AFTER_EXPIRY));
		log.info("purged {} expired refresh tokens", deleted);
	}

	private LoginResponse response(long accountId, String refresh) {
		return new LoginResponse(signer.sign(accountId), "Bearer", accessTtl.toSeconds(), refresh, Long.toString(accountId));
	}

	private OffsetDateTime now() {
		Instant i = clock.instant();
		return OffsetDateTime.ofInstant(i, ZoneOffset.UTC);
	}

	private static OffsetDateTime min(OffsetDateTime a, OffsetDateTime b) {
		return a.isBefore(b) ? a : b;
	}

	private static String newRefreshToken() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
}
