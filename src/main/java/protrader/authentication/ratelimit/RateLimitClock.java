package protrader.authentication.ratelimit;

/** Monotonic nanoseconds for the rate limiters. Production uses System.nanoTime; tests supply a bean they advance by hand. */
@FunctionalInterface
public interface RateLimitClock {

	long nanoTime();
}
