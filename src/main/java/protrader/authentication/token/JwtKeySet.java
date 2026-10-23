package protrader.authentication.token;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;

/**
 * The Ed25519 key that signs new tokens plus the public keys of retired signers that are still
 * inside the 1 h validity window. Everything published in the JWKS and accepted by the verifier
 * comes from here; kids are unique.
 */
public final class JwtKeySet {

	private final OctetKeyPair signingKey;
	private final Map<String, OctetKeyPair> publicKeys = new LinkedHashMap<>();

	public JwtKeySet(OctetKeyPair signingKey, Collection<OctetKeyPair> retiredPublicKeys) {
		if (signingKey.getKeyID() == null || signingKey.getKeyID().isEmpty() || !signingKey.isPrivate()) {
			throw new IllegalArgumentException("signing key needs a kid and the private part");
		}
		this.signingKey = signingKey;
		add(signingKey);
		retiredPublicKeys.forEach(this::add);
	}

	private void add(OctetKeyPair key) {
		OctetKeyPair pub = new OctetKeyPair.Builder(key.getCurve(), key.getX())
				.keyID(key.getKeyID())
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.EdDSA)
				.build()
				.toPublicJWK();
		if (publicKeys.putIfAbsent(pub.getKeyID(), pub) != null) {
			throw new IllegalArgumentException("duplicate kid " + pub.getKeyID());
		}
	}

	public OctetKeyPair signingKey() {
		return signingKey;
	}

	public String kid() {
		return signingKey.getKeyID();
	}

	public Optional<OctetKeyPair> publicKey(String kid) {
		return Optional.ofNullable(publicKeys.get(kid));
	}

	/** The JWKS body: {"keys":[{kty,crv,kid,use,alg,x}, ...]}, never with a private part. */
	public Map<String, Object> jwks() {
		List<Object> keys = new ArrayList<>();
		for (OctetKeyPair key : publicKeys.values()) {
			keys.add(key.toJSONObject());
		}
		return Map.of("keys", keys);
	}
}
