package protrader.authentication.web;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Keeps the two ports apart: /internal/** answers only on the internal port (the gateway sends no
 * credentials there, so the port is the protection), and user endpoints answer only on the public one.
 */
public final class PortRoutingFilter extends OncePerRequestFilter {

	private final int internalPort;
	private final ErrorWriter errors;

	public PortRoutingFilter(int internalPort, ErrorWriter errors) {
		this.internalPort = internalPort;
		this.errors = errors;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String path = request.getServletPath() + (request.getPathInfo() == null ? "" : request.getPathInfo());
		boolean internalPath = path.equals("/internal") || path.startsWith("/internal/");
		boolean health = path.equals("/healthz") || path.equals("/readyz");
		boolean onInternalPort = internalPort > 0 && request.getLocalPort() == internalPort;

		boolean allowed = onInternalPort ? (internalPath || health) : !internalPath;
		if (!allowed) {
			errors.write(response, HttpStatus.NOT_FOUND, "not_found", "no such endpoint");
			return;
		}
		chain.doFilter(request, response);
	}
}
