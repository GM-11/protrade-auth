package protrader.authentication.support;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import protrader.authentication.ratelimit.RateLimitClock;

/** Rate-limit time that only moves when a test says so. */
public class FakeRateLimitClock implements RateLimitClock {

	private final AtomicLong nanos = new AtomicLong(1_000_000L * 1_000_000_000L);

	@Override
	public long nanoTime() {
		return nanos.get();
	}

	public void advance(Duration d) {
		nanos.addAndGet(d.toNanos());
	}
}
