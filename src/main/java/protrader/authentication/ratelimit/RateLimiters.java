package protrader.authentication.ratelimit;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import protrader.authentication.config.AuthProperties;

/**
 * The limiters. State is per instance (in memory): with N instances behind a load balancer the
 * effective limits are up to N times higher. Evicting idle entries keeps the memory bounded.
 */
@Component
public class RateLimiters {

	private static final int MAX_ENTRIES = 100_000;

	private final TokenBuckets perIp;
	private final TokenBuckets loginFailuresPerEmailIp;
	private final TokenBuckets loginFailuresPerEmail;

	@Autowired
	public RateLimiters(AuthProperties props, ObjectProvider<RateLimitClock> clock) {
		this(props, MAX_ENTRIES, clock.getIfAvailable(() -> System::nanoTime));
	}

	public RateLimiters(AuthProperties props) {
		this(props, MAX_ENTRIES, System::nanoTime);
	}

	public RateLimiters(AuthProperties props, int maxEntries) {
		this(props, maxEntries, System::nanoTime);
	}

	public RateLimiters(AuthProperties props, int maxEntries, RateLimitClock clock) {
		var cfg = props.rateLimit();
		double window = cfg.loginFailureWindow().toSeconds();
		this.perIp = new TokenBuckets(cfg.perIpPerMinute(), cfg.perIpPerMinute() / 60.0, maxEntries, clock::nanoTime);
		this.loginFailuresPerEmailIp = new TokenBuckets(cfg.loginFailuresPerEmailIp(), cfg.loginFailuresPerEmailIp() / window, maxEntries, clock::nanoTime);
		this.loginFailuresPerEmail = new TokenBuckets(cfg.loginFailuresPerEmail(), cfg.loginFailuresPerEmail() / window, maxEntries, clock::nanoTime);
	}

	/** One bucket per (endpoint, client IP). */
	public TokenBuckets perIp() {
		return perIp;
	}

	/** Strict: one bucket per (lower-cased email, client IP). Keeps a targeted attacker out only from their own IP. */
	public TokenBuckets loginFailuresPerEmailIp() {
		return loginFailuresPerEmailIp;
	}

	/** Loose: one bucket per lower-cased email, whatever the IP. Caps guessing spread over many IPs. */
	public TokenBuckets loginFailuresPerEmail() {
		return loginFailuresPerEmail;
	}

	@Scheduled(fixedDelay = 60_000)
	void sweep() {
		perIp.sweep();
		loginFailuresPerEmailIp.sweep();
		loginFailuresPerEmail.sweep();
	}
}
