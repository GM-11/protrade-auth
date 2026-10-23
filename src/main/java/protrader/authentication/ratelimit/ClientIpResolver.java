package protrader.authentication.ratelimit;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Works out which client a request came from, for rate limiting. The socket peer is the default;
 * X-Forwarded-For is read only when that peer is one of the configured trusted proxies, and then
 * the right-most entry that is not itself a trusted proxy wins (everything left of it is whatever
 * the client claimed). IPv6 clients are keyed by their /64.
 */
public final class ClientIpResolver {

	private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
	private static final Pattern IPV6 = Pattern.compile("[0-9a-fA-F:.]{2,45}");

	private record Cidr(byte[] network, int prefix) {

		boolean contains(byte[] address) {
			if (address.length != network.length) {
				return false;
			}
			int fullBytes = prefix / 8;
			for (int i = 0; i < fullBytes; i++) {
				if (address[i] != network[i]) {
					return false;
				}
			}
			int rest = prefix % 8;
			if (rest == 0) {
				return true;
			}
			int mask = 0xFF << (8 - rest) & 0xFF;
			return (address[fullBytes] & mask) == (network[fullBytes] & mask);
		}
	}

	private final List<Cidr> trusted = new ArrayList<>();

	public ClientIpResolver(List<String> trustedProxyCidrs) {
		for (String c : trustedProxyCidrs) {
			trusted.add(parseCidr(c));
		}
	}

	public String resolve(HttpServletRequest request) {
		return resolve(request.getRemoteAddr(), java.util.Collections.list(request.getHeaders("X-Forwarded-For")));
	}

	/** @return a stable key for the client: the IPv4 address, or "v6:" plus the /64 prefix */
	String resolve(String remoteAddr, List<String> forwardedFor) {
		InetAddress peer = parseLiteral(remoteAddr);
		if (peer == null) {
			return "raw:" + remoteAddr;
		}
		if (!isTrusted(peer) || forwardedFor.isEmpty()) {
			return key(peer);
		}
		List<String> entries = new ArrayList<>();
		for (String header : forwardedFor) {
			for (String part : header.split(",")) {
				entries.add(part.trim());
			}
		}
		for (int i = entries.size() - 1; i >= 0; i--) {
			InetAddress hop = parseLiteral(entries.get(i));
			if (hop == null) {
				return key(peer); // garbage from our own proxy: don't guess
			}
			if (!isTrusted(hop)) {
				return key(hop);
			}
		}
		return key(peer);
	}

	private boolean isTrusted(InetAddress address) {
		byte[] raw = address.getAddress();
		return trusted.stream().anyMatch(c -> c.contains(raw));
	}

	private static String key(InetAddress address) {
		byte[] raw = address.getAddress();
		if (raw.length == 4) {
			return address.getHostAddress();
		}
		return "v6:" + HexFormat.of().formatHex(raw, 0, 8);
	}

	/** Literals only, so this never triggers a DNS lookup. */
	private static InetAddress parseLiteral(String s) {
		if (s == null) {
			return null;
		}
		String t = s.trim();
		if (!(IPV4.matcher(t).matches() || (t.indexOf(':') >= 0 && IPV6.matcher(t).matches()))) {
			return null;
		}
		try {
			return InetAddress.getByName(t);
		} catch (UnknownHostException e) {
			return null;
		}
	}

	private static Cidr parseCidr(String text) {
		String[] parts = text.trim().split("/", -1);
		InetAddress address = parseLiteral(parts[0]);
		if (address == null || parts.length > 2) {
			throw new IllegalArgumentException("TRUSTED_PROXY_CIDRS: not an IP or CIDR: " + text);
		}
		int bits = address.getAddress().length * 8;
		int prefix = bits;
		if (parts.length == 2) {
			try {
				prefix = Integer.parseInt(parts[1]);
			} catch (NumberFormatException e) {
				throw new IllegalArgumentException("TRUSTED_PROXY_CIDRS: bad prefix in " + text);
			}
			if (prefix < 0 || prefix > bits) {
				throw new IllegalArgumentException("TRUSTED_PROXY_CIDRS: bad prefix in " + text);
			}
		}
		return new Cidr(address.getAddress(), prefix);
	}
}
