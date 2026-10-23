package protrader.authentication.google;

/** What we take from a validated Google ID token. {@code sub} is the identity key; email can change. */
public record GoogleIdentity(String sub, String email, String name) {
}
