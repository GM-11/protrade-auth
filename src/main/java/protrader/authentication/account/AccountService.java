package protrader.authentication.account;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import protrader.authentication.ratelimit.RateLimitedException;
import protrader.authentication.ratelimit.RateLimiters;
import protrader.authentication.web.ApiException;

@Service
public class AccountService {

	static final int BCRYPT_STRENGTH = 12;

	private final AccountRepository accounts;
	private final RateLimiters limiters;
	private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCRYPT_STRENGTH);
	/** Same cost as real hashes; checked when there is no account or no password so timing doesn't tell which. */
	private final String dummyHash;

	public AccountService(AccountRepository accounts, RateLimiters limiters) {
		this.accounts = accounts;
		this.limiters = limiters;
		this.dummyHash = encoder.encode("dummy-password-for-timing-only");
	}

	// later: email verification, password reset / set-password for Google-only accounts, account deletion, MFA
	public long signup(String rawEmail, String password, String rawDisplayName) {
		String email = normalizeEmail(rawEmail);
		validatePassword(password);
		String displayName = validateDisplayName(rawDisplayName);
		String hash = encoder.encode(password);
		try {
			return accounts.insert(email, displayName, hash, null);
		} catch (DuplicateKeyException e) {
			// also the answer for a Google-only account: we never say which kind of account owns the email
			throw new ApiException(HttpStatus.CONFLICT, "email_taken", "email is already registered");
		}
	}

	/** The account id when email and password match; 401 bad_credentials otherwise, always the same way. */
	public long authenticate(String rawEmail, String password) {
		if (rawEmail == null || password == null) {
			throw ApiException.invalidField(rawEmail == null ? "email" : "password", "required");
		}
		String email = rawEmail.trim().toLowerCase(Locale.ROOT);

		// A token is spent per attempt and given back on success, so only failures count. Checked before
		// any BCrypt work and keyed on the email whether or not it exists, so it can't be used to probe.
		// The account is never locked: once the bucket refills, the right password works again.
		String limitKey = email.length() > 254 ? email.substring(0, 254) : email;
		long wait = limiters.loginFailures().tryAcquire(limitKey);
		if (wait > 0) {
			throw new RateLimitedException(wait);
		}
		Account account = email.length() > 254 ? null : accounts.findByEmail(email).orElse(null);
		boolean hasPassword = account != null && account.passwordHash() != null;
		// signup refuses >72 bytes, so a longer attempt can't be right (and BCrypt rejects it); still burn the same time
		boolean tooLong = password.getBytes(StandardCharsets.UTF_8).length > 72;
		boolean ok = encoder.matches(tooLong ? "x" : password, hasPassword ? account.passwordHash() : dummyHash) && !tooLong;
		if (!hasPassword || !ok) {
			throw ApiException.badCredentials();
		}
		limiters.loginFailures().refund(limitKey);
		return account.id();
	}

	public Account get(long id) {
		return accounts.findById(id).orElseThrow(ApiException::unauthorized);
	}

	static String normalizeEmail(String raw) {
		if (raw == null) {
			throw ApiException.invalidField("email", "email is required");
		}
		String email = raw.trim().toLowerCase(Locale.ROOT);
		int at = email.indexOf('@');
		if (email.length() > 254 || at <= 0 || at != email.lastIndexOf('@') || email.chars().anyMatch(c -> Character.isWhitespace(c) || Character.isISOControl(c))) {
			throw ApiException.invalidField("email", "not a valid email address");
		}
		String domain = email.substring(at + 1);
		if (!domain.contains(".") || domain.startsWith(".") || domain.endsWith(".") || domain.contains("..")) {
			throw ApiException.invalidField("email", "not a valid email address");
		}
		return email;
	}

	static void validatePassword(String password) {
		if (password == null) {
			throw ApiException.invalidField("password", "password is required");
		}
		// BCrypt ignores bytes past 72; reject instead of silently truncating
		int bytes = password.getBytes(StandardCharsets.UTF_8).length;
		if (bytes < 8 || bytes > 72) {
			throw ApiException.invalidField("password", "password must be 8 to 72 bytes (UTF-8)");
		}
	}

	static String validateDisplayName(String raw) {
		if (raw == null) {
			throw ApiException.invalidField("display_name", "display_name is required");
		}
		String name = raw.trim();
		int length = name.codePointCount(0, name.length());
		if (length < 1 || length > 40 || name.codePoints().anyMatch(Character::isISOControl)) {
			throw ApiException.invalidField("display_name", "display_name must be 1 to 40 characters, no control characters");
		}
		return name;
	}
}
