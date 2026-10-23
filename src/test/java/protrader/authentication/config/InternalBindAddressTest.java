package protrader.authentication.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.apache.catalina.connector.Connector;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;

import protrader.authentication.support.IntegrationTest;

class InternalBindAddressTest extends IntegrationTest {

	@Autowired
	AuthProperties props;

	@Test
	void theDefaultIsLoopback() {
		assertThat(props.internalBindAddress()).isEqualTo("127.0.0.1");
	}

	@Test
	void theInternalConnectorIsBoundToThatAddress() {
		TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
		SecurityConfig.internalConnectorCustomizer(props).customize(factory);
		Connector connector = factory.getAdditionalConnectors().get(0);
		assertThat(connector.getPort()).isEqualTo(props.internalPort());
		InetAddress bound = (InetAddress) connector.getProperty("address");
		assertThat(bound.isLoopbackAddress()).isTrue();
	}

	@Test
	void itCanBeOpenedUpForContainers() {
		AuthProperties open = new AuthProperties(8081, "0.0.0.0", Duration.ofHours(1), Duration.ofDays(30), Duration.ofDays(90),
				Duration.ofSeconds(10), List.of(), props.rateLimit(), props.jwt(), props.google());
		TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
		SecurityConfig.internalConnectorCustomizer(open).customize(factory);
		InetAddress bound = (InetAddress) factory.getAdditionalConnectors().get(0).getProperty("address");
		assertThat(bound.isAnyLocalAddress()).isTrue();
	}

	@Test
	void theLiveListenerRefusesConnectionsOnOtherAddresses() throws Exception {
		Optional<InetAddress> other = Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
				.flatMap(i -> Collections.list(i.getInetAddresses()).stream())
				.filter(a -> !a.isLoopbackAddress() && !a.isLinkLocalAddress() && a instanceof java.net.Inet4Address)
				.findFirst();
		assumeTrue(other.isPresent(), "no non-loopback IPv4 address on this host");

		try (Socket loopback = new Socket()) {
			loopback.connect(new InetSocketAddress("127.0.0.1", internalPort), 1000); // reachable here
		}
		try (Socket s = new Socket()) {
			org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class,
					() -> s.connect(new InetSocketAddress(other.get(), internalPort), 1000));
		}
	}
}
