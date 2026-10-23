package protrader.authentication.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import protrader.authentication.account.AccountService;
import protrader.authentication.google.GoogleAuthRequest;
import protrader.authentication.google.GoogleAuthService;
import protrader.authentication.google.GoogleNonceService;
import protrader.authentication.token.LoginResponse;
import protrader.authentication.token.TokenService;
import protrader.authentication.web.Dtos.LoginRequest;
import protrader.authentication.web.Dtos.NonceResponse;
import protrader.authentication.web.Dtos.RefreshRequest;
import protrader.authentication.web.Dtos.SignupRequest;
import protrader.authentication.web.Dtos.SignupResponse;

// later: rate limiting (429 rate_limited), Apple sign-in
@RestController
@RequestMapping("/v1/auth")
public class AuthController {

	private static final int MAX_REFRESH_TOKEN_CHARS = 512;

	private final AccountService accounts;
	private final TokenService tokens;
	private final GoogleAuthService google;
	private final GoogleNonceService nonces;

	public AuthController(AccountService accounts, TokenService tokens, GoogleAuthService google, GoogleNonceService nonces) {
		this.nonces = nonces;
		this.accounts = accounts;
		this.tokens = tokens;
		this.google = google;
	}

	@PostMapping("/signup")
	ResponseEntity<SignupResponse> signup(@JsonBody SignupRequest request) {
		long id = accounts.signup(request.email(), request.password(), request.displayName());
		return ResponseEntity.status(HttpStatus.CREATED).body(new SignupResponse(Long.toString(id)));
	}

	@PostMapping("/login")
	LoginResponse login(@JsonBody LoginRequest request) {
		return tokens.login(accounts.authenticate(request.email(), request.password()));
	}

	@PostMapping("/refresh")
	LoginResponse refresh(@JsonBody RefreshRequest request) {
		String token = request.refreshToken();
		if (token == null || token.isEmpty()) {
			throw ApiException.invalidField("refresh_token", "refresh_token is required");
		}
		if (token.length() > MAX_REFRESH_TOKEN_CHARS) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "bad_refresh_token", "invalid refresh token");
		}
		return tokens.refresh(token);
	}

	@PostMapping("/logout")
	ResponseEntity<Void> logout(@JsonBody RefreshRequest request) {
		String token = request.refreshToken();
		if (token != null && token.length() <= MAX_REFRESH_TOKEN_CHARS) {
			tokens.logout(token);
		}
		return ResponseEntity.noContent().build();
	}

	@PostMapping("/google/nonce")
	NonceResponse googleNonce() {
		return new NonceResponse(nonces.issue(), GoogleNonceService.TTL.toSeconds());
	}

	@PostMapping("/google")
	LoginResponse google(@JsonBody GoogleAuthRequest request) {
		return google.signIn(request);
	}
}
