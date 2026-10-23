package protrader.authentication.ratelimit;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import protrader.authentication.config.AuthProperties;

/**
 * The two limiters. State is per instance (in memory): with N instances behind a load balancer the
 * effective limits are up to N times higher. Evicting idle entries keeps the memory bounded.
 */
@Component
public class RateLimiters {

	private static final int MAX_ENTRIES = 100_000;

	private final TokenBuckets perIp;
	private final TokenBuckets loginFailures;

	public RateLimiters(AuthProperties props) {
		var cfg = props.rateLimit();
		this.perIp = new TokenBuckets(cfg.perIpPerMinute(), cfg.perIpPerMinute() / 60.0, MAX_ENTRIES, System::nanoTime);
		this.loginFailures = new TokenBuckets(cfg.loginFailuresPerEmail(),
				cfg.loginFailuresPerEmail() / (double) cfg.loginFailureWindow().toSeconds(), MAX_ENTRIES, System::nanoTime);
	}

	/** One bucket per (endpoint, client IP). */
	public TokenBuckets perIp() {
		return perIp;
	}

	/** One bucket per lower-cased login email; a token is spent per attempt and returned on success. */
	public TokenBuckets loginFailures() {
		return loginFailures;
	}

	@Scheduled(fixedDelay = 60_000)
	void sweep() {
		perIp.sweep();
		loginFailures.sweep();
	}
}
