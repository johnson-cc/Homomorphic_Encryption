package security.elgamal;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.Random;

import security.misc.CipherConstants;
import security.misc.NTL;

public class ElGamalKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants
{
	private int key_size = KEY_SIZE;
	private SecureRandom random = null;
	private final boolean additive;

	public ElGamalKeyPairGenerator(boolean additive) {
		this.additive = additive;
	}
	
	public void initialize(int key_size, SecureRandom random) {
		if (key_size < KEY_SIZE/2) {
			throw new IllegalArgumentException("I am allowing minimum 1024 minimum. Note it isn't safe now though." +
					"This is just to prove my implementation works though...");
		}
		this.key_size = key_size;
		this.random = random;
	}

	public KeyPair generateKeyPair() {
		long start_time;
		if(this.random == null) {
			random = new SecureRandom();
		}
		
		// (a) take a random prime p with getPrime() function. p = 2 * p' + 1 with prime(p') = true
		start_time = System.nanoTime();
		BigInteger p = getPrime(key_size, random);
		System.out.println("Obtaining p and q time: " + (System.nanoTime() - start_time)/BILLION + " seconds.");
		
		// (b) take a random element in [Z/Z[p]]* (p' order)
		BigInteger g;
		BigInteger q = p.subtract(BigInteger.ONE).divide(TWO);

		start_time = System.nanoTime();
		while (true) {
			g = NTL.RandomBnd(p);
			g = g.modPow(TWO, p);
			
			if(g.equals(BigInteger.ONE)) {
				continue;
			}
			
			if(g.equals(TWO)) {
				continue;
			}
			
			// Discard g if it divides p-1 because of the attack described
		    // in Note 11.67 (iii) in HAC
			if(p.subtract(BigInteger.ONE).mod(g).equals(BigInteger.ZERO)) {
				continue;
			}
			
			// g^{-1} must not divide p-1 because of Khadir's attack
			// described in "Conditions of the generator for forging ElGamal
			// signature", 2011
			if(!p.subtract(BigInteger.ONE).mod(g.modInverse(p)).equals(BigInteger.ZERO)) {
				break;
			}
		}
		System.out.println("Obtaining Generator g time: " + (System.nanoTime() - start_time)/BILLION + " seconds.");
		
		// (c) take x random in [0, p' - 1]
		BigInteger x = NTL.RandomBnd(q);
		BigInteger h = g.modPow(x, p);

		// secret key is (p, x) and public key is (p, g, h)
		ElGamalPrivateKey sk = new ElGamalPrivateKey(p, x, g, h, this.additive);
		ElGamalPublicKey pk = new ElGamalPublicKey(p, g, h, this.additive);
		if (this.additive) {
			System.out.println("El-Gamal Key pair generated! (Supports Addition over Ciphertext/Scalar Multiplication");
		}
		else {
			System.out.println("El-Gamal Key pair generated! (Supports Multiplication over Ciphertext)");
		}
		return new KeyPair(pk, sk);
	}

	/**
	 * Return a prime p = 2 * p' + 1
	 *
	 * @param nb_bits   is the prime representation
	 * @param prg       random
	 * @return p
	 */
	public static BigInteger getPrime(int nb_bits, Random prg) {
		BigInteger pPrime = new BigInteger(nb_bits, CERTAINTY, prg);
		// p = 2 * pPrime + 1
		BigInteger p = pPrime.multiply(TWO).add(BigInteger.ONE);

		while (!p.isProbablePrime(CERTAINTY)) 
		{
			pPrime = new BigInteger(nb_bits, CERTAINTY, prg);
			p = pPrime.multiply(TWO).add(BigInteger.ONE);
		}
		return p;
	}
}
