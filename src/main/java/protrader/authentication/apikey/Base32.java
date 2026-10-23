package protrader.authentication.apikey;

/** RFC 4648 base32 (upper case, no padding): what Go's base32.StdEncoding.WithPadding(NoPadding) gives newkey. */
final class Base32 {

	private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

	private Base32() {
	}

	static String encode(byte[] data) {
		StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
		int buffer = 0;
		int bits = 0;
		for (byte b : data) {
			buffer = (buffer << 8) | (b & 0xFF);
			bits += 8;
			while (bits >= 5) {
				out.append(ALPHABET[(buffer >> (bits - 5)) & 31]);
				bits -= 5;
			}
			buffer &= (1 << bits) - 1;
		}
		if (bits > 0) {
			out.append(ALPHABET[(buffer << (5 - bits)) & 31]);
		}
		return out.toString();
	}
}
