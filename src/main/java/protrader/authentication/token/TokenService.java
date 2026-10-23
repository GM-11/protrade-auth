package protrader.authentication.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

	public TokenService(JwtSigner signer, RefreshTokenRepository refreshTokens, TransactionTemplate tx, Clock clock, AuthProperties props) {
		this.signer = signer;
		this.refreshTokens = refreshTokens;
		this.tx = tx;
		this.clock = clock;
		this.accessTtl = props.accessTokenTtl();
		this.refreshTtl = props.refreshTokenTtl();
		this.familyMaxTtl = props.refreshFamilyMaxTtl();
	}

	/** A fresh login: new refresh-token family. */
	public LoginResponse login(long accountId) {
		OffsetDateTime now = now();
		String refresh = newRefreshToken();
		refreshTokens.insert(accountId, UUID.randomUUID(), sha256(refresh), now,
				now.plus(refreshTtl), now.plus(familyMaxTtl));
		return response(accountId, refresh);
	}

	/**
	 * Rotates a refresh token. A token that was already rotated is a replay: the whole family is
	 * revoked. Two simultaneous refreshes with one token: one wins the conditional UPDATE, the loser
	 * sees a used token and revokes the family (so the winner's new token dies too; accepted).
	 */
	public LoginResponse refresh(String token) {
		byte[] hash = sha256(token);
		Optional<LoginResponse> rotated = tx.execute(status -> {
			OffsetDateTime now = now();
			Optional<RefreshTokenRepository.Rotated> used = refreshTokens.markUsed(hash, now);
			if (used.isPresent()) {
				RefreshTokenRepository.Rotated r = used.get();
				String next = newRefreshToken();
				OffsetDateTime expires = min(now.plus(refreshTtl), r.familyExpiresAt());
				refreshTokens.insert(r.accountId(), r.familyId(), sha256(next), now, expires, r.familyExpiresAt());
				return Optional.of(response(r.accountId(), next));
			}
			refreshTokens.find(hash).filter(RefreshTokenRepository.Row::used)
					.ifPresent(row -> refreshTokens.revokeFamily(row.familyId(), now));
			return Optional.empty();
		});
		// the revoke above is committed; only now do we say no
		return rotated.orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED,
				"bad_refresh_token", "invalid refresh token"));
	}

	/** Revokes the token's whole family. Silent when the token is unknown, so it is safe to repeat. */
	public void logout(String token) {
		if (token == null || token.isEmpty()) {
			return;
		}
		byte[] hash = sha256(token);
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

	static byte[] sha256(String s) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
