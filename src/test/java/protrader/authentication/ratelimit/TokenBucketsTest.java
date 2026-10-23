package protrader.authentication.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

class TokenBucketsTest {

	private static final long SECOND = 1_000_000_000L;
	private final AtomicLong clock = new AtomicLong(1_000 * SECOND);

	@Test
	void allowsTheBurstThenAsksToWait() {
		TokenBuckets b = new TokenBuckets(3, 3 / 60.0, 100, clock::get);
		assertThat(b.tryAcquire("k")).isZero();
		assertThat(b.tryAcquire("k")).isZero();
		assertThat(b.tryAcquire("k")).isZero();
		long wait = b.tryAcquire("k");
		assertThat(wait).isBetween(1L, 20L); // one token every 20 s
		assertThat(b.tryAcquire("other")).isZero(); // keys are independent
	}

	@Test
	void refillsOverTime() {
		TokenBuckets b = new TokenBuckets(2, 2 / 60.0, 100, clock::get);
		b.tryAcquire("k");
		b.tryAcquire("k");
		assertThat(b.tryAcquire("k")).isPositive();
		clock.addAndGet(31 * SECOND);
		assertThat(b.tryAcquire("k")).isZero();
		assertThat(b.tryAcquire("k")).isPositive();
	}

	@Test
	void refundGivesATokenBackUpToCapacity() {
		TokenBuckets b = new TokenBuckets(2, 0.0001, 100, clock::get);
		b.tryAcquire("k");
		b.tryAcquire("k");
		assertThat(b.tryAcquire("k")).isPositive();
		b.refund("k");
		assertThat(b.tryAcquire("k")).isZero();
		b.refund("k");
		b.refund("k");
		b.refund("k");
		assertThat(b.tryAcquire("k")).isZero();
		assertThat(b.tryAcquire("k")).isZero();
		assertThat(b.tryAcquire("k")).isPositive(); // never more than the capacity
	}

	@Test
	void sweepDropsIdleEntriesButKeepsOnesStillInDebt() {
		TokenBuckets b = new TokenBuckets(2, 2 / 60.0, 100, clock::get);
		b.tryAcquire("idle");
		b.tryAcquire("busy");
		b.tryAcquire("busy");
		clock.addAndGet(31 * SECOND); // "idle" is whole again, "busy" has one token
		b.sweep();
		assertThat(b.size()).isEqualTo(1);
		clock.addAndGet(60 * SECOND);
		b.sweep();
		assertThat(b.size()).isZero();
	}

	@Test
	void memoryStaysBoundedUnderAFloodOfDistinctKeys() {
		TokenBuckets b = new TokenBuckets(1, 0.0001, 50, clock::get);
		for (int i = 0; i < 1_000; i++) {
			b.tryAcquire("key-" + i);
		}
		assertThat(b.size()).isLessThanOrEqualTo(50);
	}
}
