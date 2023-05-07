package security.DGK;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import security.misc.NTL;

public final class DGKPrivateKey implements Serializable, DGK_Key, PrivateKey
{
	private static final long serialVersionUID = 4574519230502483629L;

	// Private Key Parameters
	protected final BigInteger p;
	protected final BigInteger q;
	protected final BigInteger vp;
	protected final BigInteger vq;
	protected final Map <BigInteger, Long> LUT;

	// Public key parameters
	protected final BigInteger n;
	protected final BigInteger g;
	protected final BigInteger h;
	protected final long u;
	protected final BigInteger bigU;

	// Key Parameters
	protected final int l;
	protected final int t;
	protected final int k;

	// Signature
	public final BigInteger v;

	public DGKPrivateKey (BigInteger p, BigInteger q, BigInteger vp,
			BigInteger vq, DGKPublicKey pubKey) {
		this.p = p;
		this.q = q;
		this.vp = vp;
		this.vq = vq;
		this.v = vp.multiply(vq);

		// Public Key Parameters
		this.n = pubKey.n;
		this.g = pubKey.g;
		this.h = pubKey.h;
		this.u = pubKey.u;
		this.bigU = pubKey.bigU;

		// Key Parameters
		this.l = pubKey.l;
		this.t = pubKey.t;
		this.k = pubKey.k;

		// I already know the size of my map, so just initialize the size now to avoid memory waste!
		this.LUT = new HashMap<>((int) this.u, (float) 1.0);

		// Now that I have public key parameters, build LUT!
		this.generategLUT();
	}

	public void writeKey(String dgk_private_key_file) {
		LUT.clear();
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(dgk_private_key_file))) {
			oos.writeObject(this);
			oos.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static DGKPrivateKey readKey(String dgk_private_key) {
		DGKPrivateKey sk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(dgk_private_key))) {
			sk = (DGKPrivateKey) ois.readObject();
		} catch (IOException | ClassNotFoundException e) {
			throw new RuntimeException(e);
		}
		sk.generategLUT();
		return sk;
	}

	private void generategLUT() {
		BigInteger gvp = NTL.POSMOD(this.g.modPow(this.vp, this.p), this.p);
		for (long i = 0; i < this.u; ++i)
		{
			BigInteger decipher = gvp.modPow(BigInteger.valueOf(i), this.p);
			this.LUT.put(decipher, i);
		}
	}

	// Not going to print private key parameters...
	public String toString() {
		String answer = "";
		answer += "n: " + this.n + '\n';
		answer += "g: " + this.g + '\n';
		answer += "h: " + this.h + '\n';
		answer += "u: " + this.bigU + '\n';
		answer += "l: " + this.l + '\n';
		answer += "t: " + this.t + '\n';
		answer += "k: " + this.k + '\n';
		// COMMENTED OUT TO HIDE SECRET KEY PARAMETERS
		return answer;
	}

	public BigInteger getU() {
		return this.bigU;
	}

	public BigInteger getN() {
		return this.n;
	}

	public int getL() {
		return this.l;
	}

	public String getAlgorithm() {
		return "DGK";
	}

	public String getFormat() {
		return "PKCS#8";
	}

	public byte[] getEncoded() {
		return null;
	}

	public boolean equals (Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DGKPrivateKey that = (DGKPrivateKey) o;
		return this.toString().equals(that.toString());
	}
}