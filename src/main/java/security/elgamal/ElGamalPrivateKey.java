package security.elgamal;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import security.misc.CipherConstants;

public final class ElGamalPrivateKey implements ElGamal_Key, Serializable, PrivateKey, Runnable, CipherConstants
{
	//Private Key parameters
	final BigInteger x;
	final Map <BigInteger, BigInteger> LUT;

	// Taken from ElGamal Public Key
	final BigInteger p;
	final BigInteger g;
	private final BigInteger h;
	boolean additive;

	private static final long serialVersionUID = 9160045368787508459L;

	public ElGamalPrivateKey(BigInteger p, BigInteger x, BigInteger g, BigInteger h, boolean additive) {
		this.p = p;
		this.x = x;
		this.g = g;
		this.h = h;
		this.additive = additive;
		if(additive) {
			this.LUT = new HashMap<>(FIELD_SIZE.intValue(), (float) 1.0);
			this.decrypt_table();
		}
		else {
			this.LUT = null;
		}
	}

	public void set_additive(boolean additive) {
		this.additive = additive;
	}

	public String getAlgorithm()
	{
		return "ElGamal";
	}

	public String getFormat() 
	{
		return "PKCS#8";
	}

	public byte[] getEncoded() 
	{
		return null;
	}

	// Generate Lookup Table, plain text space is [0, p - 1)
	private void decrypt_table() {
		// Get maximum size of x - y + r + 2^l
		// Assume maximum value is u: biggest value in DGK which is the closest prime from 2^l l = 16 default.
		BigInteger decrypt_size = FIELD_SIZE.add(FIELD_SIZE).subtract(TWO).add(TWO.pow(16));
		long start_time = System.nanoTime();
		System.out.println("Building Lookup Table g^m --> m for ElGamal");
		BigInteger message = BigInteger.ZERO;
		while (!message.equals(decrypt_size)) {
			BigInteger gm = this.g.modPow(message, this.p);
			this.LUT.put(gm, message);
			message = message.add(BigInteger.ONE);
		}

		// For negative numbers, go from p - 2 and go down a bit
		message = this.p.subtract(TWO);
		while (!message.equals(this.p.subtract(BigInteger.TEN))) {
			BigInteger gm = this.g.modPow(message, this.p);
			this.LUT.put(gm, message);
			message = message.subtract(BigInteger.ONE);
		}
		System.out.println("Finished Building Lookup Table g^m --> m for ElGamal in " + 
				(System.nanoTime() - start_time)/BigInteger.TEN.pow(9).longValue() + " seconds");
	}

	public void run() 
	{
		decrypt_table();
	}

	public String toString() {
		String answer = "";
		answer += "p=" + this.p + '\n';
		answer += "g=" + this.g + '\n';
		answer += "h=" + this.h + '\n';
		//answer += "s=" + this.x + '\n';
		return answer;
	}

	public BigInteger getP() 
	{
		return this.p;
	}
}
