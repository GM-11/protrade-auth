package protrader.authentication.apikey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import protrader.authentication.web.ApiException;

@Service
public class ApiKeyService {

	static final int MAX_ACTIVE_KEYS = 10;
	static final int MAX_LABEL = 60;
	private static final SecureRandom RANDOM = new SecureRandom();

	/** The one-time view of a new key: the only place the secret ever appears. */
	public record Created(String keyId, String secret, String label, OffsetDateTime createdAt) {
	}

	/** Gateway snapshot: version plus every key, disabled ones included. */
	public record Snapshot(long version, List<ApiKeyRepository.Row> keys) {
	}

	private final ApiKeyRepository repo;
	private final TransactionTemplate tx;
	private final TransactionTemplate snapshotTx;
	private final Clock clock;

	public ApiKeyService(ApiKeyRepository repo, TransactionTemplate tx, PlatformTransactionManager txManager, Clock clock) {
		this.repo = repo;
		this.tx = tx;
		// version and keys must come from one consistent view, or the gateway could see a new version with old keys
		this.snapshotTx = new TransactionTemplate(txManager);
		this.snapshotTx.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		this.snapshotTx.setReadOnly(true);
		this.clock = clock;
	}

	public Created create(long accountId, String rawLabel) {
		String label = validateLabel(rawLabel);
		byte[] idBytes = new byte[10];
		byte[] secretBytes = new byte[32];
		RANDOM.nextBytes(idBytes);
		RANDOM.nextBytes(secretBytes);
		String keyId = "PK" + Base32.encode(idBytes);
		String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(secretBytes);
		OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);

		tx.executeWithoutResult(status -> {
			repo.lockAccount(accountId);
			if (repo.countActive(accountId) >= MAX_ACTIVE_KEYS) {
				throw ApiException.invalidField("label", "limit of " + MAX_ACTIVE_KEYS + " active API keys reached");
			}
			repo.insert(keyId, accountId, sha256Hex(secret), label, now);
			repo.bumpVersion();
		});
		return new Created(keyId, secret, label, now);
	}

	public List<ApiKeyRepository.Row> list(long accountId) {
		return repo.listForAccount(accountId);
	}

	/** Disables (never deletes) so the key stays in the list and the gateway sees the change. */
	public void disable(long accountId, String keyId) {
		tx.executeWithoutResult(status -> {
			Optional<ApiKeyRepository.Row> row = repo.findOwnedForUpdate(keyId, accountId);
			if (row.isEmpty()) {
				// same answer for "not yours" and "doesn't exist"
				throw new ApiException(HttpStatus.NOT_FOUND, "key_not_found", "no such API key");
			}
			if (!row.get().disabled()) {
				repo.disable(keyId);
				repo.bumpVersion();
			}
		});
	}

	/** Empty when the caller already has this version or newer. */
	public Optional<Snapshot> snapshotIfNewer(long ifNewerThan) {
		return snapshotTx.execute(status -> {
			long version = repo.version();
			if (ifNewerThan >= version) {
				return Optional.empty();
			}
			return Optional.of(new Snapshot(version, repo.all()));
		});
	}

	static String validateLabel(String raw) {
		String label = raw == null ? "" : raw.trim();
		if (label.codePointCount(0, label.length()) > MAX_LABEL || label.codePoints().anyMatch(Character::isISOControl)) {
			throw ApiException.invalidField("label", "label must be at most 60 characters, no control characters");
		}
		return label;
	}

	static String sha256Hex(String s) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
