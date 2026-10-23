package protrader.authentication.web;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** One line per request: method, path, status, duration, account if known. Never headers, query or bodies. */
public final class RequestLogFilter extends OncePerRequestFilter {

	private static final Logger log = LoggerFactory.getLogger("protrader.authentication.request");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		long start = System.nanoTime();
		try {
			chain.doFilter(request, response);
		} finally {
			long ms = (System.nanoTime() - start) / 1_000_000;
			Object account = request.getAttribute(JwtAuthFilter.ACCOUNT_ATTRIBUTE);
			log.info("{} {} -> {} in {}ms account={}", request.getMethod(), request.getRequestURI(), response.getStatus(), ms,
					account == null ? "-" : account);
		}
	}
}
