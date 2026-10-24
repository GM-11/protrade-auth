package protrader.authentication.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** All env-driven settings; the env names are mapped to these keys in application.yml. */
@ConfigurationProperties("auth")
public record AuthProperties(
		int internalPort,
		String internalBindAddress,
		Duration accessTokenTtl,
		Duration refreshTokenTtl,
		Duration refreshFamilyMaxTtl,
		Duration refreshReuseGrace,
		List<String> corsAllowedOrigins,
		RateLimit rateLimit,
		Jwt jwt,
		Google google) {

	/** The gateway rejects exp - iat > 1 h, so this is also our ceiling. */
	public static final Duration MAX_ACCESS_TOKEN_TTL = Duration.ofHours(1);

	public AuthProperties {
		if (accessTokenTtl.isZero() || accessTokenTtl.isNegative() || accessTokenTtl.compareTo(MAX_ACCESS_TOKEN_TTL) > 0) {
			throw new IllegalStateException("ACCESS_TOKEN_TTL must be > 0 and at most 1h (the gateway rejects longer tokens), got " + accessTokenTtl);
		}
		if (refreshTokenTtl.isZero() || refreshTokenTtl.isNegative()) {
			throw new IllegalStateException("REFRESH_TOKEN_TTL must be positive");
		}
		if (refreshFamilyMaxTtl.compareTo(refreshTokenTtl) < 0) {
			throw new IllegalStateException("REFRESH_FAMILY_MAX_TTL must be at least REFRESH_TOKEN_TTL");
		}
		if (refreshReuseGrace.isNegative()) {
			throw new IllegalStateException("REFRESH_REUSE_GRACE must not be negative");
		}
		corsAllowedOrigins = clean(corsAllowedOrigins);
	}

	/** Per-instance, in-memory limits (see the README). */
	public record RateLimit(int perIpPerMinute, int loginFailuresPerEmailIp, int loginFailuresPerEmail, Duration loginFailureWindow,
			List<String> trustedProxyCidrs) {

		public RateLimit {
			if (perIpPerMinute < 1 || loginFailuresPerEmailIp < 1 || loginFailuresPerEmail < 1
					|| loginFailureWindow.isZero() || loginFailureWindow.isNegative()) {
				throw new IllegalStateException("rate-limit settings must be positive");
			}
			if (loginFailuresPerEmail < loginFailuresPerEmailIp) {
				throw new IllegalStateException("RATE_LIMIT_LOGIN_FAILURES_PER_EMAIL (" + loginFailuresPerEmail
						+ ") must be at least RATE_LIMIT_LOGIN_FAILURES_PER_EMAIL_IP (" + loginFailuresPerEmailIp + ")");
			}
			trustedProxyCidrs = clean(trustedProxyCidrs);
		}
	}

	public record Jwt(String issuer, String audience, String kid, String privateKeyFile, String retiredPublicKeysDir) {
	}

	public record Google(String clientId, String clientSecret, List<String> allowedRedirectUris,
			List<String> extraAudiences, String discoveryUrl) {

		public Google {
			allowedRedirectUris = clean(allowedRedirectUris);
			extraAudiences = clean(extraAudiences);
		}
	}

	private static List<String> clean(List<String> in) {
		if (in == null) {
			return List.of();
		}
		return in.stream().map(String::trim).filter(s -> !s.isEmpty()).toList();
	}
}
