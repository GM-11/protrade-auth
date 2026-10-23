package protrader.authentication.token;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import protrader.authentication.config.AuthProperties;

/** Builds the {@link JwtKeySet} from config: a key file, or an ephemeral key in the dev profile. */
public final class JwtKeyLoader {

	private static final Logger log = LoggerFactory.getLogger(JwtKeyLoader.class);

	private JwtKeyLoader() {
	}

	public static JwtKeySet load(AuthProperties.Jwt cfg, boolean devProfile) {
		OctetKeyPair signing;
		if (cfg.privateKeyFile() == null || cfg.privateKeyFile().isBlank()) {
			if (!devProfile) {
				throw new IllegalStateException("JWT_PRIVATE_KEY_FILE is required outside the dev profile");
			}
			signing = ephemeral(cfg.kid());
			log.warn("*** DEV PROFILE: no JWT_PRIVATE_KEY_FILE, generated an ephemeral signing key kid={}. "
					+ "Every restart changes the kid and invalidates all tokens issued so far. ***", signing.getKeyID());
		} else {
			if (cfg.kid() == null || cfg.kid().isBlank()) {
				throw new IllegalStateException("JWT_KID is required when JWT_PRIVATE_KEY_FILE is set");
			}
			signing = fromFile(Path.of(cfg.privateKeyFile()), cfg.kid());
		}
		return new JwtKeySet(signing, retired(cfg.retiredPublicKeysDir()));
	}

	static OctetKeyPair ephemeral(String kid) {
		try {
			byte[] seed = new byte[32];
			new java.security.SecureRandom().nextBytes(seed);
			String id = (kid == null || kid.isBlank()) ? "dev-" + HexFormat.of().formatHex(seed, 0, 4) : kid;
			return keyPair(seed, id);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("cannot generate Ed25519 key", e);
		}
	}

	/** PKCS#8 Ed25519 private key, PEM or bare base64 of the DER. */
	static OctetKeyPair fromFile(Path file, String kid) {
		try {
			String text = Files.readString(file, StandardCharsets.US_ASCII);
			String b64 = text.lines().filter(l -> !l.startsWith("-----")).reduce("", String::concat).replaceAll("\\s", "");
			byte[] der = Base64.getDecoder().decode(b64);
			EdECPrivateKey key = (EdECPrivateKey) KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
			return keyPair(key.getBytes().orElseThrow(), kid);
		} catch (IOException | GeneralSecurityException | IllegalArgumentException | ClassCastException e) {
			throw new IllegalStateException("cannot load JWT_PRIVATE_KEY_FILE " + file + ": " + e.getMessage(), e);
		}
	}

	private static OctetKeyPair keyPair(byte[] seed, String kid) throws GeneralSecurityException {
		Ed25519Sign.KeyPair kp = Ed25519Sign.KeyPair.newKeyPairFromSeed(seed);
		return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(kp.getPublicKey()))
				.d(Base64URL.encode(kp.getPrivateKey()))
				.keyID(kid)
				.build();
	}

	/** Each *.json / *.jwk file in the directory holds one public JWK (a private part, if present, is dropped). */
	static List<OctetKeyPair> retired(String dir) {
		List<OctetKeyPair> out = new ArrayList<>();
		if (dir == null || dir.isBlank()) {
			return out;
		}
		try (Stream<Path> files = Files.list(Path.of(dir))) {
			for (Path f : files.filter(p -> p.toString().endsWith(".json") || p.toString().endsWith(".jwk")).sorted().toList()) {
				JWK jwk = JWK.parse(Files.readString(f, StandardCharsets.UTF_8));
				if (!(jwk instanceof OctetKeyPair okp) || !Curve.Ed25519.equals(okp.getCurve()) || okp.getKeyID() == null) {
					throw new IllegalStateException("retired key " + f + " must be an Ed25519 OKP JWK with a kid");
				}
				out.add(okp.toPublicJWK());
			}
		} catch (IOException | java.text.ParseException e) {
			throw new IllegalStateException("cannot read JWT_RETIRED_PUBLIC_KEYS_DIR " + dir + ": " + e.getMessage(), e);
		}
		return out;
	}
}
