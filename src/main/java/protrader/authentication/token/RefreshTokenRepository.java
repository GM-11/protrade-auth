package protrader.authentication.token;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class RefreshTokenRepository {

	/** What a successful rotation hands back: whose token it was and the chain it belongs to. */
	public record Rotated(long accountId, UUID familyId, OffsetDateTime familyExpiresAt) {
	}

	/** A token row looked up by hash (only the fields reuse detection needs). */
	public record Row(UUID familyId, boolean used) {
	}

	private final JdbcClient jdbc;

	public RefreshTokenRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	public void insert(long accountId, UUID familyId, byte[] hash, OffsetDateTime now, OffsetDateTime expiresAt, OffsetDateTime familyExpiresAt) {
		jdbc.sql("""
				INSERT INTO refresh_tokens (account_id, family_id, token_sha256, created_at, expires_at, family_expires_at)
				VALUES (?, ?, ?, ?, ?, ?)""")
				.params(accountId, familyId, hash, now, expiresAt, familyExpiresAt)
				.update();
	}

	/** The one atomic step that makes rotation single-use: only one caller can flip used_at. */
	public Optional<Rotated> markUsed(byte[] hash, OffsetDateTime now) {
		return jdbc.sql("""
				UPDATE refresh_tokens SET used_at = ?
				WHERE token_sha256 = ? AND used_at IS NULL AND revoked_at IS NULL
				  AND expires_at > ? AND family_expires_at > ?
				RETURNING account_id, family_id, family_expires_at""")
				.params(now, hash, now, now)
				.query((rs, i) -> new Rotated(rs.getLong("account_id"), rs.getObject("family_id", UUID.class),
						rs.getObject("family_expires_at", OffsetDateTime.class)))
				.optional();
	}

	public Optional<Row> find(byte[] hash) {
		return jdbc.sql("SELECT family_id, used_at IS NOT NULL AS used FROM refresh_tokens WHERE token_sha256 = ?")
				.param(hash)
				.query((rs, i) -> new Row(rs.getObject("family_id", UUID.class), rs.getBoolean("used")))
				.optional();
	}

	public int revokeFamily(UUID familyId, OffsetDateTime now) {
		return jdbc.sql("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL")
				.params(now, familyId)
				.update();
	}

	public int revokeAllForAccount(long accountId, OffsetDateTime now) {
		return jdbc.sql("UPDATE refresh_tokens SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL")
				.params(now, accountId)
				.update();
	}

	public int deleteExpiredBefore(OffsetDateTime cutoff) {
		return jdbc.sql("DELETE FROM refresh_tokens WHERE expires_at < ?").param(cutoff).update();
	}
}
