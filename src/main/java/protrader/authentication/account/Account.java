package protrader.authentication.account;

import java.time.Instant;

public record Account(long id, String email, String displayName, String passwordHash, String googleSub, Instant createdAt) {
}
