package protrader.authentication.account;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

@Repository
public class AccountRepository {

	private static final String COLUMNS = "id, email, display_name, password_hash, google_sub, created_at";

	private final JdbcClient jdbc;

	public AccountRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	private static Account map(ResultSet rs, int row) throws SQLException {
		return new Account(
				rs.getLong("id"),
				rs.getString("email"),
				rs.getString("display_name"),
				rs.getString("password_hash"),
				rs.getString("google_sub"),
				rs.getObject("created_at", OffsetDateTime.class).toInstant());
	}

	public Optional<Account> findById(long id) {
		return jdbc.sql("SELECT " + COLUMNS + " FROM accounts WHERE id = ?").param(id).query(AccountRepository::map).optional();
	}

	public Optional<Account> findByEmail(String email) {
		return jdbc.sql("SELECT " + COLUMNS + " FROM accounts WHERE email = ?").param(email).query(AccountRepository::map).optional();
	}

	/** Row-locked, so concurrent Google logins linking the same email serialise. */
	public Optional<Account> findByEmailForUpdate(String email) {
		return jdbc.sql("SELECT " + COLUMNS + " FROM accounts WHERE email = ? FOR UPDATE").param(email).query(AccountRepository::map).optional();
	}

	public Optional<Account> findByGoogleSub(String sub) {
		return jdbc.sql("SELECT " + COLUMNS + " FROM accounts WHERE google_sub = ?").param(sub).query(AccountRepository::map).optional();
	}

	/** Throws DuplicateKeyException when the email (or google_sub) is taken. */
	public long insert(String email, String displayName, String passwordHash, String googleSub) {
		KeyHolder keys = new GeneratedKeyHolder();
		jdbc.sql("INSERT INTO accounts (email, display_name, password_hash, google_sub) VALUES (?, ?, ?, ?)")
				.params(email, displayName, passwordHash, googleSub)
				.update(keys, "id");
		return keys.getKey().longValue();
	}

	/** Links a Google identity and drops the password (see GoogleAuthService for why). */
	public void linkGoogle(long id, String googleSub) {
		jdbc.sql("UPDATE accounts SET google_sub = ?, password_hash = NULL WHERE id = ?").params(googleSub, id).update();
	}
}
