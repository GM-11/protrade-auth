package protrader.authentication.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

class ClientIpResolverTest {

	private final ClientIpResolver untrusting = new ClientIpResolver(List.of());
	private final ClientIpResolver behindProxy = new ClientIpResolver(List.of("10.0.0.0/8", "192.168.1.5", "fd00::/8"));

	@Test
	void theSocketPeerIsTheDefault() {
		assertThat(untrusting.resolve("203.0.113.9", List.of())).isEqualTo("203.0.113.9");
	}

	@Test
	void forwardedForIsIgnoredWhenThePeerIsNotATrustedProxy() {
		assertThat(untrusting.resolve("203.0.113.9", List.of("1.2.3.4"))).isEqualTo("203.0.113.9");
		assertThat(behindProxy.resolve("203.0.113.9", List.of("1.2.3.4"))).isEqualTo("203.0.113.9");
	}

	@Test
	void aTrustedProxyVouchesForTheRightMostNonProxyEntry() {
		// the client claimed to be 9.9.9.9; our proxy appended the real peer 203.0.113.7
		assertThat(behindProxy.resolve("10.1.2.3", List.of("9.9.9.9, 203.0.113.7"))).isEqualTo("203.0.113.7");
		// a chain of our own proxies is skipped from the right
		assertThat(behindProxy.resolve("10.1.2.3", List.of("9.9.9.9, 203.0.113.7, 10.5.5.5, 192.168.1.5"))).isEqualTo("203.0.113.7");
		// several header lines count as one list
		assertThat(behindProxy.resolve("10.1.2.3", List.of("9.9.9.9", "203.0.113.7"))).isEqualTo("203.0.113.7");
	}

	@Test
	void withoutTheHeaderOrWithOnlyProxiesThePeerIsUsed() {
		assertThat(behindProxy.resolve("10.1.2.3", List.of())).isEqualTo("10.1.2.3");
		assertThat(behindProxy.resolve("10.1.2.3", List.of("10.9.9.9"))).isEqualTo("10.1.2.3");
	}

	@Test
	void garbageFromTheProxyFallsBackToThePeer() {
		assertThat(behindProxy.resolve("10.1.2.3", List.of("1.2.3.4, not-an-ip"))).isEqualTo("10.1.2.3");
		assertThat(behindProxy.resolve("10.1.2.3", List.of("evil.example.com"))).isEqualTo("10.1.2.3");
	}

	@Test
	void ipv6ClientsAreKeyedByTheir64() {
		String a = untrusting.resolve("2001:db8:1:2:aaaa:bbbb:cccc:dddd", List.of());
		String b = untrusting.resolve("2001:db8:1:2:1111:2222:3333:4444", List.of());
		String c = untrusting.resolve("2001:db8:1:3::1", List.of());
		assertThat(a).isEqualTo(b).isNotEqualTo(c).startsWith("v6:");
	}

	@Test
	void badCidrsFailStartup() {
		assertThatThrownBy(() -> new ClientIpResolver(List.of("10.0.0.0/33"))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ClientIpResolver(List.of("proxy.example.com"))).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void cidrBoundariesAreRespected() {
		ClientIpResolver r = new ClientIpResolver(List.of("172.16.0.0/12"));
		assertThat(r.resolve("172.31.255.255", List.of("5.5.5.5"))).isEqualTo("5.5.5.5"); // inside /12
		assertThat(r.resolve("172.32.0.1", List.of("5.5.5.5"))).isEqualTo("172.32.0.1"); // just outside
	}
}
