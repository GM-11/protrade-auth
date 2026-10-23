package protrader.authentication.web;

/** Who the verified bearer token says is calling. */
public record AccountPrincipal(long accountId) {
}
