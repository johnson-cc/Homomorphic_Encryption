package security.dgk;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;

public final class DGKKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants
{
	// Default parameters
	private int l = 16;
	private int t = 160;
	private int k = KEY_SIZE;

	public static void main(String []  args) throws IOException {
		System.out.println("Creating DGK Key pair");
		String dgk_private_key_file = "dgk";
		String dgk_public_key_file = "dgk.pub";
		KeyPair dgk;
		DGKPublicKey pk;
		DGKPrivateKey sk;

		// Create the Key
		DGKKeyPairGenerator pa = new DGKKeyPairGenerator();
		pa.initialize(KEY_SIZE, null);
		dgk = pa.generateKeyPair();
		pk = (DGKPublicKey) dgk.getPublic();
		sk = (DGKPrivateKey) dgk.getPrivate();

		// Write the key to a file
		pk.writeKey(dgk_public_key_file);
		sk.writeKey(dgk_private_key_file);
	}

	public DGKKeyPairGenerator() {
		this.initialize(this.k, null);
	}
	
	/**
	 * Initialize DGK Key pair generator and sets DGK parameters
	 * @param l - sets size of plaintext
	 * @param t - security parameter
	 * @param k - number of bits of keys
	 */
	public DGKKeyPairGenerator(int l, int t, int k) throws HomomorphicException
	{
		if (k < KEY_SIZE) {
			throw new IllegalArgumentException("Minimum strength of 2048 bits required! Safe until 2030...");
		}

		if (l < 0 || l > 32) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: plaintext space must be less than 32 bits");
		}
		
		if (l > t || t > k) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have l < k < t");
		}
		
		if (k/2 < t + l + 1) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}
		
		if (t % 2 != 0) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: t must be divisible by 2 ");
		}
		
		if (k % 2 != 0) {
			throw new IllegalArgumentException("Require even number of bits!");
		}
		if (k < 1024) {
			throw new IllegalArgumentException("Minimum strength of 1024 bits required!");
		}
		
		this.l = l;
		this.t = t;
		this.k = k;
		this.initialize(this.k, null);
	}

	public int getL()
	{
		return this.l;
	}
	
	public void setL(int l) throws HomomorphicException
	{
		if (l < 0 || l > 32) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: plaintext space must be less than 32 bits");
		}

		if (l > this.t || this.t > this.k) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (this.k/2 < this.t + l + 1) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}
		this.l = l;
	}
	
	public int getT()
	{
		return this.t;
	}
	
	public void setT(int t) throws HomomorphicException
	{
		if (this.l > t || t > this.k) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have l < k < t");
		}
		
		if (this.k/2 < t + this.l + 1) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}
		
		if (t % 2 != 0) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: t must be divisible by 2 ");
		}
		this.t = t;
	}
	
	public int getK() {
		return this.k;
	}
	
	public void setK(int k) throws HomomorphicException {
		if (this.l > this.t || this.t > k) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (k/2 < this.t + this.l + 1) {
			throw new HomomorphicException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}
		this.k = k;
	}

	public void initialize(int k, SecureRandom random) {
		if (k < KEY_SIZE) {
			throw new IllegalArgumentException("Minimum strength of 2048 bits required!");
		}
		this.k = k;
	}

	/**
	 * @return DGK Key Pair
	 */
	public KeyPair generateKeyPair() {
		long start_time = System.nanoTime();

		DGKPublicKey public_key;
		DGKPrivateKey private_key;
		
		System.out.println("Generating Keys...");

		BigInteger p, rp;
		BigInteger q, rq;
		BigInteger g, h ;
		BigInteger n, r ;
		BigInteger u = TWO.pow(this.l);
		BigInteger vp, vq, vpvq, tmp;

		while(true)
		{
			//Following the instruction as stated on DGK C++ counterpart
			u = u.nextProbablePrime();
			vp = new BigInteger(this.t, CERTAINTY, this.rnd);//(160, 40, random)
			vq = new BigInteger(this.t, CERTAINTY, this.rnd);//(160, 40, random)
			vpvq = vp.multiply(vq);
			tmp = u.multiply(vp);
			System.out.println("Completed generating vp, vq");

			int needed_bits = this.k/2 - (tmp.bitLength());

			// Generate rp until p is prime such that u * vp divides p-1
			do
			{
				rp = new BigInteger(needed_bits, rnd);
				rp = rp.setBit(needed_bits - 1);

				/*
				 * p = rp * u * vp + 1
				 * u | p - 1
				 * vp | p - 1
				 */
				p = rp.multiply(tmp).add(BigInteger.ONE);
			}
			while(!p.isProbablePrime(CERTAINTY));

			tmp = u.multiply(vq);
			needed_bits = this.k/2 - (tmp.bitLength());
			do
			{
				// Same method for q than for p
				rq = new BigInteger(needed_bits, rnd);
				rq = rq.setBit(needed_bits -1);
				q = rq.multiply(tmp).add(BigInteger.ONE); // q = rq*(vq*u) + 1

				/*
				 * q - 1 | rq * vq * u
				 * Therefore,
				 * c^{vp} = g^{vp*m} (mod n) because
				 * rq | (q - 1)
				 */
			}
			while(!q.isProbablePrime(CERTAINTY));
			//Thus we ensure that q is a prime, with p-1 divides the prime numbers vq and u
			if(!NTL.POSMOD(rq, u).equals(BigInteger.ZERO) &&
					!NTL.POSMOD(rp, u).equals(BigInteger.ZERO))
			{
				break;
			}

		}
	
		n = p.multiply(q);
		tmp = rp.multiply(rq).multiply(u);
		System.out.println("While Loop 1: n, p and q is generated.");
		
		while(true)
		{
			//Generate n bit random number
			r = NTL.generateXBitRandom(n.bitLength());	
			h = r.modPow(tmp, n); // h = r^{rp*rq*u} (mod n)
			
			if (h.equals(BigInteger.ONE))
			{
				continue;
			}
			
			if (h.modPow(vp,n).equals(BigInteger.ONE))
			{
				continue;//h^{vp}(mod n) = 1
			}
			
			if (h.modPow(vq,n).equals(BigInteger.ONE))
			{
				continue;//h^{vq}(mod n) = 1
			}
			
			if (h.modPow(u, n).equals(BigInteger.ONE))
			{
				continue;//h^{u}(mod n) = 1
			}
			
			if (h.modPow(u.multiply(vq), n).equals(BigInteger.ONE))
			{
				continue;//h^{u*vq} (mod n) = 1
			}
			
			if (h.modPow(u.multiply(vp), n).equals(BigInteger.ONE))
			{
				continue;//h^{u*vp} (mod n) = 1
			}
			
			if (h.gcd(n).equals(BigInteger.ONE))
			{
				break;//(h, n) = 1
			}
		}
		
		BigInteger rprq = rp.multiply(rq);
		System.out.println("While loop 2: h is generated");
		
		while(true)
		{
			r = NTL.generateXBitRandom(n.bitLength());
			g = r.modPow(rprq, n); //g = r^{rp*rq}(mod n)
			
			if (g.equals(BigInteger.ONE))
			{
				continue;// g = 1
			}
			
			if (!g.gcd(n).equals(BigInteger.ONE))
			{
				continue;//(g, n) must be relatively prime
			}
			// h can still be of order u, vp, vq , or a combination of them different that u, vp, vq
			if (g.modPow(u, n).equals(BigInteger.ONE))
			{
				continue;//g^{u} (mod n) = 1
			}
			if (g.modPow(u.multiply(u), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u} (mod n) = 1
			}
			if (g.modPow(u.multiply(u).multiply(vp), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u*vp} (mod n) = 1
			}
			
			if (g.modPow(u.multiply(u).multiply(vq), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u*vp} (mod n) = 1
			}

			if (g.modPow(vp, n).equals(BigInteger.ONE))
			{
				continue;//g^{vp} (mod n) = 1
			}

			if (g.modPow(vq, n).equals(BigInteger.ONE))
			{
				continue;//g^{vq} (mod n) = 1
			}

			if (g.modPow(u.multiply(vq), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*vq}(mod n) = 1
			}

			if (g.modPow(u.multiply(vp), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*vp} (mod n) = 1
			}

			if (g.modPow(vpvq, n).equals(BigInteger.ONE))
			{
				continue;//g^{vp*vq} (mod n) == 1
			}

			if (NTL.POSMOD(g, p).modPow(vp, p).equals(BigInteger.ONE))
			{
				continue; //g^{vp} (mod p) == 1
			}

			if ((NTL.POSMOD(g,p).modPow(u, p).equals(BigInteger.ONE)))
			{
				continue;//g^{u} (mod p) = 1
			}

			if (NTL.POSMOD(g, q).modPow(vq, q).equals(BigInteger.ONE))
			{
				continue;//g^{vq}(mod q) == 1
			}

			if ((NTL.POSMOD(g, q).modPow(u, q).equals(BigInteger.ONE)))
			{
				continue;//g^{u}(mod q)
			}
			break;
		}
		System.out.println("While loop 3: g is generated");

		System.out.println("Generating hashmaps...");
		public_key =  new DGKPublicKey(n, g, h, u, this.l, this.t, this.k);
		private_key = new DGKPrivateKey(p, q, vp, vq, public_key);
		boolean no_skip_public_key_maps = true;
		if(no_skip_public_key_maps) {
			public_key.run();
		}
		System.out.println("FINISHED WITH DGK KEY GENERATION in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
		return new KeyPair(public_key, private_key);
	}

	public String toString() {
		String s = "";
		s += "l = " + l;
		s += "t = " + t;
		s += "k = " + k;
		return s;
	}
}
