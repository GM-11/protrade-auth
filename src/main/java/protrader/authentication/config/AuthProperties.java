package protrader.authentication.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** All env-driven settings; the env names are mapped to these keys in application.yml. */
@ConfigurationProperties("auth")
public record AuthProperties(
		int internalPort,
		Duration accessTokenTtl,
		Duration refreshTokenTtl,
		Duration refreshFamilyMaxTtl,
		List<String> corsAllowedOrigins,
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
		corsAllowedOrigins = clean(corsAllowedOrigins);
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
