package protrader.authentication.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Hashes {

	private Hashes() {
	}

	public static byte[] sha256(String s) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
