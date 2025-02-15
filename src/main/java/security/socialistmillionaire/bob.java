package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierPrivateKey;

public class bob extends socialist_millionaires implements bob_interface
{
	public bob(KeyPair first, KeyPair second, KeyPair third) {
		parse_key_pairs(first, second, third);
	}
	/**
	 * Create a bob instance for running extending protocols such as comparing 
	 * encrypted numbers
	 * @throws IllegalArgumentException
	 * If first is not a Paillier Keypair or second is not a DGK key pair or third is not ElGamal Keypair
	 */
	public bob (Socket socket,
			KeyPair first, KeyPair second, KeyPair third)
					throws IOException, IllegalArgumentException {
		set_socket(socket);
		parse_key_pairs(first, second, third);
	}

	private void parse_key_pairs(KeyPair first, KeyPair second, KeyPair third) {
		if (first.getPublic() instanceof PaillierPublicKey) {
			this.paillier_public = (PaillierPublicKey) first.getPublic();
			this.paillier_private = (PaillierPrivateKey) first.getPrivate();
			if(second.getPublic() instanceof DGKPublicKey) {
				this.dgk_public = (DGKPublicKey) second.getPublic();
				this.dgk_private = (DGKPrivateKey) second.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Obtained Paillier Key Pair, Not DGK Key pair!");
			}
		}
		else if (first.getPublic() instanceof DGKPublicKey) {
			this.dgk_public = (DGKPublicKey) first.getPublic();
			this.dgk_private = (DGKPrivateKey) first.getPrivate();
			if (second.getPublic() instanceof PaillierPublicKey) {
				this.paillier_public = (PaillierPublicKey) second.getPublic();
				this.paillier_private = (PaillierPrivateKey) second.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Obtained DGK Key Pair, Not Paillier Key pair!");
			}
		}

		if(third != null) {
			if (third.getPublic() instanceof ElGamalPublicKey) {
				this.el_gamal_public = (ElGamalPublicKey) third.getPublic();
				this.el_gamal_private= (ElGamalPrivateKey) third.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Third Keypair MUST BE AN EL GAMAL KEY PAIR!");
			}
		}

		this.isDGK = false;
		powL = TWO.pow(dgk_public.getL());
	}

	public void set_socket(Socket socket) throws IOException {
		if(socket != null) {
			this.toAlice = new ObjectOutputStream(socket.getOutputStream());
			this.fromAlice = new ValidatingObjectInputStream(socket.getInputStream());
			this.fromAlice.accept(
					java.math.BigInteger.class,
					java.lang.Number.class,
					java.util.HashMap.class,
					java.lang.Long.class,
					security.elgamal.ElGamal_Ciphertext.class
			);
			this.fromAlice.accept("[B");
			this.fromAlice.accept("[L*");
		}
		else {
			throw new NullPointerException("Client Socket is null!");
		}
	}
	/**
	 * if Alice wants to sort a list of encrypted numbers, use this method if you 
	 * will consistently sort using Protocol 2
	 */
	public void sort()
			throws IOException, ClassNotFoundException, HomomorphicException {
		long start_time = System.nanoTime();
		int counter = 0;
		while(fromAlice.readBoolean()) {
			++counter;
			this.Protocol2();
		}
		System.out.println("Protocol 2 was used " + counter + " times!");
		System.out.println("Protocol 2 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
	}

	/**
	 * Please review "Improving the DGK comparison protocol" - Protocol 1
	 *
	 * @param y - plaintext value
	 * @return boolean
	 * @throws IllegalArgumentException - if y has more bits than is supported by provided DGK keys
	 */
	public boolean Protocol1(BigInteger y)
			throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
		// Constraint...
		if(y.bitLength() > dgk_public.getL()) {
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, y is: " + y.bitLength() + " bits");
		}

		Object in;
		int deltaB = 0;
		BigInteger [] C;
		BigInteger temp;

		//Step 1: Bob sends encrypted bits to Alice
		BigInteger [] EncY = new BigInteger[y.bitLength()];
		for (int i = 0; i < y.bitLength(); i++) {
			EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), dgk_public);
		}
		toAlice.writeObject(EncY);
		toAlice.flush();
		
		// Step 2: Alice...
		// Step 3: Alice...
		// Step 4: Alice...
		// Step 5: Alice...
		// Step 6: Check if one of the numbers in C_i is decrypted to 0.
		in = fromAlice.readObject();
		if(in instanceof BigInteger[]) {
			C = (BigInteger []) in;
		}
		else if (in instanceof BigInteger) {
			temp = (BigInteger) in;
			if (temp.equals(BigInteger.ONE)) {
				return true;
			}
			else if (temp.equals(BigInteger.ZERO)) {
				return false;
			}
			else {
				throw new IllegalArgumentException("This shouldn't be possible...");
			}
		}
		else {
			throw new IllegalArgumentException("Protocol 1, Step 6: Invalid object: " + in.getClass().getName());
		}

		for (BigInteger C_i: C) {
			if (DGKOperations.decrypt(C_i, dgk_private) == 0) {
				deltaB = 1;
				break;
			}
		}
		// Run Extra steps to help Alice decrypt Delta
		return decrypt_protocol_one(deltaB);
	}

	protected boolean decrypt_protocol_one(int deltaB) throws IOException, ClassNotFoundException, HomomorphicException {
		Object o;
		BigInteger delta;

		// Step 7: UNOFFICIAL
		// Inform Alice what deltaB is

		// Party B encrypts delta_B using his public key and sends it to Alice. Upon receiving
		// delta_B, party A computes the encryption of delta as
		// 1- delta = delta_b if delta_a = 0
		// 2- delta = 1 - delta_b otherwise if delta_a = 1.
		toAlice.writeObject(DGKOperations.encrypt(deltaB, dgk_public));
		toAlice.flush();

		// Step 8: UNOFFICIAL
		// Alice sends the encrypted answer...
		// For now, Bob doesn't need to know the decryption, so Alice did blind it.
		// So just decrypt and return the value.
		o = fromAlice.readObject();
		if (o instanceof BigInteger) {
			delta = BigInteger.valueOf(DGKOperations.decrypt((BigInteger) o, dgk_private));
			toAlice.writeObject(delta);
			toAlice.flush();
			return delta.equals(BigInteger.ONE);
		}
		else {
			throw new IllegalArgumentException("Invalid response from Alice in Step 8: " + o.getClass().getName());
		}
	}

	// Bob gets encrypted input from alice to decrypt comparison result
	protected boolean decrypt_protocol_two() throws IOException, ClassNotFoundException, HomomorphicException {
		Object x;
		int answer = -1;

		x = fromAlice.readObject();
		if (x instanceof BigInteger) {
			if(isDGK) {
				long decrypt = DGKOperations.decrypt((BigInteger) x, dgk_private);
				// IF SOMETHING HAPPENS...GET POST MORTEM HERE
				if (decrypt != 0 && dgk_public.getU().longValue() - 1 != decrypt) {
					throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
				}

				if (dgk_public.getu() - 1 == decrypt) {
					answer = 0;
				}
				else {
					answer = 1;
				}
			}
			else {
				answer = PaillierCipher.decrypt((BigInteger) x, paillier_private).intValue();
			}
			toAlice.writeInt(answer);
			toAlice.flush();
		}
		else {
			throw new IllegalArgumentException("Protocol 4, Step 8 Failed " + x.getClass().getName());
		}
		// IF SOMETHING HAPPENS...GET POST MORTEM HERE
		if (answer != 0 && answer != 1) {
			throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
		}
		return answer == 1;
	}

	public boolean Protocol2()
			throws ClassNotFoundException, IOException, HomomorphicException {
		// Step 1: Receive z from Alice
		// Get the input and output streams
		int answer;
		Object x;
		BigInteger beta;
		BigInteger z;
		
		if(isDGK) {
			throw new HomomorphicException("COMPARING ENCRYPTED DGK VALUES WITH PROTOCOL 2 IS NOT ALLOWED," +
					" PLEASE USE PROTOCOL 4!");
		}

		//Step 1: get [[z]] from Alice
		x = fromAlice.readObject();
		if (x instanceof BigInteger) {
			z = (BigInteger) x;
		}
		else {
			throw new IllegalArgumentException("Bob Step 1: Invalid Object!" + x.getClass().getName());
		}
		
		//[[z]] = [[x - y + 2^l + r]]
		z = PaillierCipher.decrypt(z, paillier_private);
		
		// Step 2: compute Beta = z (mod 2^l),
		beta = NTL.POSMOD(z, powL);
		
		// Step 3: Alice computes r (mod 2^l) (Alpha)
		// Step 4: Run Protocol 3
		Protocol1(beta);
		
		// Step 5: Send [[z/2^l]], Alice has the solution from Protocol 3 already...
		toAlice.writeObject(PaillierCipher.encrypt(z.divide(powL), paillier_public));
		toAlice.flush();
		
		// Step 6 - 7: Alice Computes [[x >= y]]
		
		// Step 8 (UNOFFICIAL): Alice needs the answer for [[x >= y]]
		return decrypt_protocol_two();
	}


	public void multiplication() 
			throws IOException, ClassNotFoundException, HomomorphicException
	{
		Object in;
		BigInteger x_prime;
		BigInteger y_prime;
		
		// Step 2
		in = fromAlice.readObject();
		if(in instanceof BigInteger) {
			x_prime = (BigInteger) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[x']] from Alice: " + in.getClass().getName());
		}
		
		in = fromAlice.readObject();
		if(in instanceof BigInteger) {
			y_prime = (BigInteger) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[y']] from Alice: " + in.getClass().getName());		
		}
		
		// Step 3
		if(isDGK) {
			x_prime = BigInteger.valueOf(DGKOperations.decrypt(x_prime, dgk_private));
			y_prime = BigInteger.valueOf(DGKOperations.decrypt(y_prime, dgk_private));
			// To avoid myself throwing errors of encryption must be [0, U), mod it now!
			toAlice.writeObject(DGKOperations.encrypt(x_prime.multiply(y_prime).mod(dgk_public.getU()), dgk_public));
		}
		else {
			x_prime = PaillierCipher.decrypt(x_prime, paillier_private);
			y_prime = PaillierCipher.decrypt(y_prime, paillier_private);
			// To avoid myself throwing errors of encryption must be [0, N), mod it now!
			toAlice.writeObject(PaillierCipher.encrypt(x_prime.multiply(y_prime).mod(paillier_public.getN()), paillier_public));
		}
		toAlice.flush();
	}
	
	public void division(long divisor) 
			throws ClassNotFoundException, IOException, HomomorphicException
	{
		BigInteger c;
		BigInteger z;
		Object alice = fromAlice.readObject();
		if(alice instanceof BigInteger)	{
			z = (BigInteger) alice;
		}
		else {
			throw new IllegalArgumentException("Division: No BigInteger found: " + alice.getClass().getName());
		}
		
		if(isDGK) {
			z = BigInteger.valueOf(DGKOperations.decrypt(z, dgk_private));
		}
		else {
			z = PaillierCipher.decrypt(z, paillier_private);
		}
		
		if(!FAST_DIVIDE) {
			Protocol1(z.mod(BigInteger.valueOf(divisor)));
		}
		// MAYBE IF OVER FLOW HAPPENS?
		// Modified_Protocol3(z.mod(powL), z);	
	
		c = z.divide(BigInteger.valueOf(divisor));
		if(isDGK) {
			toAlice.writeObject(DGKOperations.encrypt(c, dgk_public));	
		}
		else {
			toAlice.writeObject(PaillierCipher.encrypt(c, paillier_public));
		}
		toAlice.flush();
		/*
		 *  Unlike Comparison, it is decided Bob shouldn't know the answer.
		 *  This is because Bob KNOWS d, and can decrypt [x/d]
		 *  
		 *  Since the idea is not leak the numbers themselves, 
		 *  it is decided Bob shouldn't receive [x/d]
		 */
	}
	
	public void sendPublicKeys() throws IOException
	{
		if(dgk_public != null) {
			toAlice.writeObject(dgk_public);
			System.out.println("Bob sent DGK Public Key to Alice");
		}
		else {
			toAlice.writeObject(BigInteger.ZERO);
		}
		if(paillier_public != null) {
			toAlice.writeObject(paillier_public);
			System.out.println("Bob sent Paillier Public Key to Alice");
		}
		else {
			toAlice.writeObject(BigInteger.ZERO);
		}
		if(el_gamal_public != null) {
			toAlice.writeObject(el_gamal_public);
			System.out.println("Bob sent ElGamal Public Key to Alice");
		}
		else {
			toAlice.writeObject(BigInteger.ZERO);
		}
		toAlice.flush();
	}
}