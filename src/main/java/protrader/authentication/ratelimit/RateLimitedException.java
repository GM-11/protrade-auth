package protrader.authentication.ratelimit;

import org.springframework.http.HttpStatus;

import protrader.authentication.web.ApiException;

public class RateLimitedException extends ApiException {

	private final long retryAfterSeconds;

	public RateLimitedException(long retryAfterSeconds) {
		super(HttpStatus.TOO_MANY_REQUESTS, "rate_limited", "too many requests, retry later");
		this.retryAfterSeconds = retryAfterSeconds;
	}

	public long retryAfterSeconds() {
		return retryAfterSeconds;
	}
}
