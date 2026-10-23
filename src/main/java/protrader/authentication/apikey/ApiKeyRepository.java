package protrader.authentication.apikey;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class ApiKeyRepository {

	public record Row(String keyId, long accountId, String secretSha256, String label, boolean disabled, OffsetDateTime createdAt) {
	}

	private final JdbcClient jdbc;

	public ApiKeyRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	private static Row map(ResultSet rs, int i) throws SQLException {
		return new Row(rs.getString("key_id"), rs.getLong("account_id"), rs.getString("secret_sha256"),
				rs.getString("label"), rs.getBoolean("disabled"), rs.getObject("created_at", OffsetDateTime.class));
	}

	/** Serialises key creation per account so the 10-key cap can't be raced past. */
	public void lockAccount(long accountId) {
		jdbc.sql("SELECT id FROM accounts WHERE id = ? FOR UPDATE").param(accountId).query().listOfRows();
	}

	public int countActive(long accountId) {
		return jdbc.sql("SELECT count(*) FROM api_keys WHERE account_id = ? AND NOT disabled").param(accountId).query(Integer.class).single();
	}

	public void insert(String keyId, long accountId, String secretSha256, String label, OffsetDateTime createdAt) {
		jdbc.sql("INSERT INTO api_keys (key_id, account_id, secret_sha256, label, created_at) VALUES (?, ?, ?, ?, ?)")
				.params(keyId, accountId, secretSha256, label, createdAt)
				.update();
	}

	public List<Row> listForAccount(long accountId) {
		return jdbc.sql("SELECT * FROM api_keys WHERE account_id = ? ORDER BY created_at, key_id").param(accountId).query(ApiKeyRepository::map).list();
	}

	public Optional<Row> findOwnedForUpdate(String keyId, long accountId) {
		return jdbc.sql("SELECT * FROM api_keys WHERE key_id = ? AND account_id = ? FOR UPDATE").params(keyId, accountId).query(ApiKeyRepository::map).optional();
	}

	public void disable(String keyId) {
		jdbc.sql("UPDATE api_keys SET disabled = true WHERE key_id = ?").param(keyId).update();
	}

	public void bumpVersion() {
		jdbc.sql("UPDATE api_key_version SET version = version + 1").update();
	}

	public long version() {
		return jdbc.sql("SELECT version FROM api_key_version").query(Long.class).single();
	}

	public List<Row> all() {
		return jdbc.sql("SELECT * FROM api_keys ORDER BY key_id").query(ApiKeyRepository::map).list();
	}
}
