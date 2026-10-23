package protrader.authentication.ratelimit;

import java.io.IOException;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import protrader.authentication.web.ErrorWriter;

/**
 * Per-IP limit on the unauthenticated, expensive endpoints. Runs before the request body is read
 * and before any BCrypt call, so a flood costs us almost nothing.
 */
public final class RateLimitFilter extends OncePerRequestFilter {

	static final Set<String> LIMITED_PATHS = Set.of(
			"/v1/auth/signup", "/v1/auth/login", "/v1/auth/refresh", "/v1/auth/google", "/v1/auth/google/nonce");

	private final RateLimiters limiters;
	private final ClientIpResolver clients;
	private final ErrorWriter errors;

	public RateLimitFilter(RateLimiters limiters, ClientIpResolver clients, ErrorWriter errors) {
		this.limiters = limiters;
		this.clients = clients;
		this.errors = errors;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String path = request.getServletPath() + (request.getPathInfo() == null ? "" : request.getPathInfo());
		if ("POST".equals(request.getMethod()) && LIMITED_PATHS.contains(path)) {
			long wait = limiters.perIp().tryAcquire(path + "|" + clients.resolve(request));
			if (wait > 0) {
				response.setHeader("Retry-After", Long.toString(wait));
				errors.write(response, HttpStatus.TOO_MANY_REQUESTS, "rate_limited", "too many requests, retry later");
				return;
			}
		}
		chain.doFilter(request, response);
	}
}
