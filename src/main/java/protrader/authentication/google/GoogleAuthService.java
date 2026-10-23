package protrader.authentication.google;

import java.util.Locale;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import protrader.authentication.account.Account;
import protrader.authentication.account.AccountRepository;
import protrader.authentication.config.AuthProperties;
import protrader.authentication.token.LoginResponse;
import protrader.authentication.token.RefreshTokenRepository;
import protrader.authentication.token.TokenService;
import protrader.authentication.web.ApiException;

@Service
public class GoogleAuthService {

	private static final Logger log = LoggerFactory.getLogger(GoogleAuthService.class);
	private static final Pattern PKCE_VERIFIER = Pattern.compile("[A-Za-z0-9\\-._~]{43,128}");
	private static final int MAX_NAME = 40;

	private final GoogleTokenExchange exchange;
	private final GoogleIdTokenVerifier verifier;
	private final AccountRepository accounts;
	private final RefreshTokenRepository refreshTokens;
	private final TokenService tokens;
	private final TransactionTemplate tx;
	private final java.time.Clock clock;
	private final AuthProperties.Google config;

	public GoogleAuthService(GoogleTokenExchange exchange, GoogleIdTokenVerifier verifier, AccountRepository accounts,
			RefreshTokenRepository refreshTokens, TokenService tokens, TransactionTemplate tx, java.time.Clock clock,
			AuthProperties props) {
		this.exchange = exchange;
		this.verifier = verifier;
		this.accounts = accounts;
		this.refreshTokens = refreshTokens;
		this.tokens = tokens;
		this.tx = tx;
		this.clock = clock;
		this.config = props.google();
	}

	public LoginResponse signIn(GoogleAuthRequest req) {
		validate(req);
		GoogleIdentity identity;
		try {
			identity = req.code() != null ? fromCode(req) : fromIdToken(req);
		} catch (GoogleRejectedException e) {
			log.info("google sign-in rejected: {}", e.getMessage());
			throw ApiException.badCredentials();
		} catch (GoogleUnavailableException e) {
			log.warn("google unavailable: {}", e.getMessage());
			throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "google_unavailable", "Google sign-in is unavailable, try again");
		}
		long accountId = resolveAccount(identity);
		return tokens.login(accountId);
	}

	private GoogleIdentity fromCode(GoogleAuthRequest req) {
		String idToken = exchange.exchange(req.code(), req.codeVerifier(), req.redirectUri());
		// a nonce in the token was created by the client, which checks it; we only check ours
		return verifier.verify(idToken, null, false);
	}

	private GoogleIdentity fromIdToken(GoogleAuthRequest req) {
		return verifier.verify(req.idToken(), req.nonce(), true);
	}

	/** Shape and allow-list checks; throws 422 invalid_field. Called before anything leaves the building. */
	public void validate(GoogleAuthRequest req) {
		boolean codeShape = req.code() != null || req.codeVerifier() != null || req.redirectUri() != null;
		boolean tokenShape = req.idToken() != null || req.nonce() != null;
		if (codeShape && tokenShape) {
			throw ApiException.invalidField(req.idToken() != null ? "id_token" : "nonce", "give either code+code_verifier+redirect_uri or id_token, not both");
		}
		if (!codeShape && !tokenShape) {
			throw ApiException.invalidField("code", "give code+code_verifier+redirect_uri or id_token");
		}
		if (codeShape) {
			if (req.code() == null || req.code().isBlank() || req.code().length() > 2048) {
				throw ApiException.invalidField("code", "code is required");
			}
			if (req.codeVerifier() == null || !PKCE_VERIFIER.matcher(req.codeVerifier()).matches()) {
				throw ApiException.invalidField("code_verifier", "code_verifier must be 43-128 characters of [A-Za-z0-9-._~]");
			}
			if (req.redirectUri() == null || !config.allowedRedirectUris().contains(req.redirectUri())) {
				throw ApiException.invalidField("redirect_uri", "redirect_uri is not allowed");
			}
		} else {
			if (req.idToken() == null || req.idToken().isBlank() || req.idToken().length() > 8192) {
				throw ApiException.invalidField("id_token", "id_token is required");
			}
			if (req.nonce() != null && (req.nonce().isEmpty() || req.nonce().length() > 256)) {
				throw ApiException.invalidField("nonce", "nonce must be 1-256 characters");
			}
		}
	}

	private long resolveAccount(GoogleIdentity identity) {
		// two first-time logins at once: the loser hits a unique index, rolls back and re-runs as a lookup
		for (int attempt = 0; ; attempt++) {
			try {
				return tx.execute(status -> resolveOnce(identity));
			} catch (DuplicateKeyException e) {
				if (attempt >= 2) {
					throw e;
				}
			}
		}
	}

	private long resolveOnce(GoogleIdentity identity) {
		var bySub = accounts.findByGoogleSub(identity.sub());
		if (bySub.isPresent()) {
			return bySub.get().id();
		}
		String email = identity.email().trim().toLowerCase(Locale.ROOT);
		var byEmail = accounts.findByEmailForUpdate(email);
		if (byEmail.isPresent()) {
			Account existing = byEmail.get();
			if (identity.sub().equals(existing.googleSub())) {
				// a concurrent first login for this same identity committed between our two lookups
				return existing.id();
			}
			if (existing.googleSub() != null) {
				// the address now belongs to a different Google identity than the one linked: never take over
				log.warn("google sign-in refused: email already linked to another Google identity (account {})", existing.id());
				throw ApiException.badCredentials();
			}
			// Signup doesn't verify email ownership yet, so this password may belong to someone who
			// pre-registered the victim's address: drop it and every session it created.
			accounts.linkGoogle(existing.id(), identity.sub());
			refreshTokens.revokeAllForAccount(existing.id(), java.time.OffsetDateTime.ofInstant(clock.instant(), java.time.ZoneOffset.UTC));
			return existing.id();
		}
		return accounts.insert(email, displayName(identity.name(), email), null, identity.sub());
	}

	static String displayName(String name, String email) {
		String base = name == null ? "" : strip(name);
		if (base.isEmpty()) {
			base = strip(email.substring(0, email.indexOf('@')));
		}
		if (base.isEmpty()) {
			base = "user";
		}
		int[] cps = base.codePoints().limit(MAX_NAME).toArray();
		return new String(cps, 0, cps.length);
	}

	private static String strip(String s) {
		StringBuilder sb = new StringBuilder();
		s.codePoints().filter(cp -> !Character.isISOControl(cp)).forEach(sb::appendCodePoint);
		return sb.toString().trim();
	}
}
