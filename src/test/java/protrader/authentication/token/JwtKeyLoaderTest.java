package protrader.authentication.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.jwk.OctetKeyPair;

import protrader.authentication.config.AuthProperties;
import protrader.authentication.support.TestTokens;

class JwtKeyLoaderTest {

	@TempDir
	Path dir;

	private static AuthProperties.Jwt cfg(String kid, String keyFile, String retiredDir) {
		return new AuthProperties.Jwt("iss", "aud", kid, keyFile, retiredDir);
	}

	@Test
	void devProfileGeneratesAnEphemeralKey() {
		JwtKeySet a = JwtKeyLoader.load(cfg("", "", ""), true);
		JwtKeySet b = JwtKeyLoader.load(cfg("", "", ""), true);
		assertThat(a.kid()).startsWith("dev-").isNotEqualTo(b.kid());
		String token = new JwtSigner(a, "iss", "aud", Duration.ofHours(1), Clock.systemUTC()).sign(9);
		assertThat(new JwtVerifier(a, "iss", "aud", Clock.systemUTC()).verify(token)).isPresent();
	}

	@Test
	void otherProfilesRefuseToStartWithoutAKey() {
		assertThatThrownBy(() -> JwtKeyLoader.load(cfg("k1", "", ""), false))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("JWT_PRIVATE_KEY_FILE");
	}

	@Test
	void keyFileNeedsAKid() throws Exception {
		Path file = writePem(newKeyPair());
		assertThatThrownBy(() -> JwtKeyLoader.load(cfg("", file.toString(), ""), false))
				.isInstanceOf(IllegalStateException.class).hasMessageContaining("JWT_KID");
	}

	@Test
	void loadsPkcs8PemAndSignsWithTheMatchingPublicKey() throws Exception {
		KeyPair pair = newKeyPair();
		JwtKeySet keys = JwtKeyLoader.load(cfg("prod-1", writePem(pair).toString(), ""), false);
		assertThat(keys.kid()).isEqualTo("prod-1");

		String token = new JwtSigner(keys, "iss", "aud", Duration.ofHours(1), Clock.systemUTC()).sign(1234);
		String[] parts = token.split("\\.");
		java.security.Signature sig = java.security.Signature.getInstance("Ed25519");
		sig.initVerify(pair.getPublic()); // the public half of the file's key, computed by the JDK
		sig.update((parts[0] + "." + parts[1]).getBytes());
		assertThat(sig.verify(Base64.getUrlDecoder().decode(parts[2]))).isTrue();
	}

	@Test
	void loadsBareBase64Der() throws Exception {
		KeyPair pair = newKeyPair();
		Path file = dir.resolve("bare.b64");
		Files.writeString(file, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
		assertThat(JwtKeyLoader.load(cfg("k", file.toString(), ""), false).kid()).isEqualTo("k");
	}

	@Test
	void badKeyFileFailsStartupWithoutLeakingItsContent() throws Exception {
		Path file = dir.resolve("bad.pem");
		Files.writeString(file, "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LXN0dWZm\n-----END PRIVATE KEY-----\n");
		assertThatThrownBy(() -> JwtKeyLoader.load(cfg("k", file.toString(), ""), false))
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void retiredPublicKeysJoinTheJwksButNeverGetPrivateParts() throws Exception {
		OctetKeyPair old = TestTokens.newKey("old-1");
		Files.writeString(dir.resolve("old-1.json"), old.toJSONString()); // even a file with "d" must not leak it
		Files.writeString(dir.resolve("ignored.txt"), "not a key");
		JwtKeySet keys = JwtKeyLoader.load(cfg("new-1", writePem(newKeyPair()).toString(), dir.toString()), false);
		assertThat(keys.publicKey("old-1")).isPresent();
		assertThat(keys.publicKey("new-1")).isPresent();
		for (Object key : (java.util.List<?>) keys.jwks().get("keys")) {
			assertThat(((java.util.Map<?, ?>) key).containsKey("d")).isFalse();
		}
		assertThat(keys.publicKey("old-1").orElseThrow().isPrivate()).isFalse();
	}

	@Test
	void retiredKeyWithoutKidFailsStartup() throws Exception {
		Files.writeString(dir.resolve("nokid.json"), "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}");
		assertThatThrownBy(() -> JwtKeyLoader.retired(dir.toString())).isInstanceOf(IllegalStateException.class);
	}

	private static KeyPair newKeyPair() throws Exception {
		return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
	}

	private Path writePem(KeyPair pair) throws Exception {
		String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPrivate().getEncoded());
		Path file = Files.createTempFile(dir, "key", ".pem");
		Files.writeString(file, "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n");
		return file;
	}
}
