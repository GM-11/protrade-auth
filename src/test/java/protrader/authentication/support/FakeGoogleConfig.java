package protrader.authentication.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

@TestConfiguration
public class FakeGoogleConfig {

	@Bean
	@Primary
	FakeGoogle fakeGoogle() {
		return new FakeGoogle();
	}
}
