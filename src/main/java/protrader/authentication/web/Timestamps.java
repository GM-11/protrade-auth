package protrader.authentication.web;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** RFC 3339 UTC with milliseconds: 2026-10-17T08:30:00.123Z. */
final class Timestamps {

	private static final DateTimeFormatter FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

	private Timestamps() {
	}

	static String format(Instant instant) {
		return FORMAT.format(instant);
	}

	static String format(OffsetDateTime time) {
		return format(time.toInstant());
	}
}
