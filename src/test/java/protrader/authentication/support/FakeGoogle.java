package protrader.authentication.support;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import protrader.authentication.google.GoogleIdTokenVerifier;
import protrader.authentication.google.GoogleIdentity;
import protrader.authentication.google.GoogleRejectedException;
import protrader.authentication.google.GoogleTokenExchange;
import protrader.authentication.google.GoogleUnavailableException;

/** Stands in for Google in controller tests: ID tokens are plain strings registered here. */
public class FakeGoogle implements GoogleTokenExchange, GoogleIdTokenVerifier {

	public record Call(String code, String verifier, String redirectUri) {
	}

	private final Map<String, GoogleIdentity> tokens = new ConcurrentHashMap<>();
	private final Map<String, String> codes = new ConcurrentHashMap<>();
	public final List<Call> exchanges = new ArrayList<>();
	public volatile boolean down;

	public void register(String idToken, GoogleIdentity identity) {
		tokens.put(idToken, identity);
	}

	public void registerCode(String code, String idToken) {
		codes.put(code, idToken);
	}

	@Override
	public String exchange(String code, String codeVerifier, String redirectUri) {
		if (down) {
			throw new GoogleUnavailableException("down", null);
		}
		exchanges.add(new Call(code, codeVerifier, redirectUri));
		String t = codes.get(code);
		if (t == null) {
			throw new GoogleRejectedException("unknown code");
		}
		return t;
	}

	@Override
	public GoogleIdentity verify(String idToken, String nonce, boolean allowExtraAudiences) {
		GoogleIdentity id = tokens.get(idToken);
		if (id == null) {
			throw new GoogleRejectedException("unknown token");
		}
		return id;
	}
}
