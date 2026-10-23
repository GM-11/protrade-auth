package protrader.authentication.ratelimit;

import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Keyed token buckets, in memory. A key that has been idle long enough to be full again is
 * indistinguishable from one never seen, so idle entries are dropped by {@link #sweep()} and,
 * as a hard bound, when the map reaches {@code maxEntries}.
 */
public final class TokenBuckets {

	private static final class Bucket {
		double tokens;
		long lastNanos;

		Bucket(double tokens, long lastNanos) {
			this.tokens = tokens;
			this.lastNanos = lastNanos;
		}
	}

	private final double capacity;
	private final double refillPerNano;
	private final int maxEntries;
	private final LongSupplier nanos;
	private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

	/** @param capacity burst size; @param refillPerSecond tokens added per second */
	public TokenBuckets(int capacity, double refillPerSecond, int maxEntries, LongSupplier nanos) {
		this.capacity = capacity;
		this.refillPerNano = refillPerSecond / 1_000_000_000.0;
		this.maxEntries = maxEntries;
		this.nanos = nanos;
	}

	/** Takes one token. Returns 0 if taken, otherwise the whole seconds to wait for the next token (at least 1). */
	public long tryAcquire(String key) {
		if (buckets.size() >= maxEntries && !buckets.containsKey(key)) {
			makeRoom();
		}
		long[] wait = {0};
		buckets.compute(key, (k, b) -> {
			long now = nanos.getAsLong();
			Bucket bucket = refilled(b, now);
			if (bucket.tokens >= 1) {
				bucket.tokens -= 1;
			} else {
				wait[0] = Math.max(1, (long) Math.ceil((1 - bucket.tokens) / refillPerNano / 1_000_000_000.0));
			}
			return bucket;
		});
		return wait[0];
	}

	/** Gives a token back (a login that succeeded does not count as a failure). */
	public void refund(String key) {
		buckets.computeIfPresent(key, (k, b) -> {
			Bucket bucket = refilled(b, nanos.getAsLong());
			bucket.tokens = Math.min(capacity, bucket.tokens + 1);
			return bucket;
		});
	}

	/** Drops every entry that has refilled completely. */
	public void sweep() {
		long now = nanos.getAsLong();
		for (String key : buckets.keySet()) {
			buckets.computeIfPresent(key, (k, b) -> refilled(b, now).tokens >= capacity ? null : b);
		}
	}

	int size() {
		return buckets.size();
	}

	private Bucket refilled(Bucket b, long now) {
		if (b == null) {
			return new Bucket(capacity, now);
		}
		b.tokens = Math.min(capacity, b.tokens + (now - b.lastNanos) * refillPerNano);
		b.lastNanos = now;
		return b;
	}

	private void makeRoom() {
		sweep();
		// still full of live entries (a flood of distinct keys): forget some arbitrary ones rather than grow without bound
		Iterator<String> it = buckets.keySet().iterator();
		int toDrop = maxEntries / 10 + 1;
		while (buckets.size() >= maxEntries && it.hasNext() && toDrop-- > 0) {
			buckets.remove(it.next());
		}
	}
}
