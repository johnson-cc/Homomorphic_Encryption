package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import security.dgk.DGKOperations;
import security.dgk.DGKPublicKey;

import security.elgamal.ElGamalPublicKey;

import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;

import java.util.List;

public class alice extends socialist_millionaires implements alice_interface {

	public alice() {
		this.isDGK = false;
	}

	public alice (Socket clientSocket) throws IOException {
		if(clientSocket != null) {
			set_socket(clientSocket);
		}
		else {
			throw new NullPointerException("Client Socket is null!");
		}
		this.isDGK = false;
	}

	public void set_socket(Socket socket) throws IOException {
		toBob = new ObjectOutputStream(socket.getOutputStream());
		fromBob = new ValidatingObjectInputStream(socket.getInputStream());
		this.fromBob.accept(
				security.paillier.PaillierPublicKey.class,
				security.dgk.DGKPublicKey.class,
				security.elgamal.ElGamalPublicKey.class,
				security.gm.GMPublicKey.class,
				java.math.BigInteger.class,
				java.lang.Number.class,
				security.elgamal.ElGamal_Ciphertext.class,
				java.util.HashMap.class,
				java.lang.Long.class
		);
		this.fromBob.accept("[B");
		this.fromBob.accept("[L*");
	}

	/**
	 * Please see Protocol 1 with Bob which has parameter y
	 * Computes the truth value of X <= Y
	 * @param x - plaintext value
	 * @return X <= Y
	 * @throws IOException - Socket Errors
	 * @throws ClassNotFoundException - Required for casting objects
	 * @throws IllegalArgumentException - If x or y have more bits 
	 * than that is supported by the DGK Keys provided
	 */
	public boolean Protocol1(BigInteger x)
			throws IOException, IllegalArgumentException, HomomorphicException, ClassNotFoundException {
		// Constraint...
		if(x.bitLength() > dgk_public.getL()) {
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
		}

		int delta_a = rnd.nextInt(2);
		Object in;

		BigInteger [] Encrypted_Y;
		BigInteger [] C;
		BigInteger [] XOR;

		// Step 1: Get Y bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[]) {
			Encrypted_Y = (BigInteger []) in;
		}
		else {
			throw new IllegalArgumentException("Protocol 1 Step 1: Missing Y-bits! Got " + in.getClass().getName());
		}

		if (x.bitLength() < Encrypted_Y.length) {
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			System.out.println("Shouldn't be here: x <= y bits");
			return true;
		}
		else if(x.bitLength() > Encrypted_Y.length) {
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			System.out.println("Shouldn't be here: x > y bits");
			return false;
		}

		// Otherwise, if the bit size is equal, proceed!
		// Step 2: compute Encrypted X XOR Y
		XOR = new BigInteger[Encrypted_Y.length];
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			if (NTL.bit(x, i) == 1) {
				XOR[i] = DGKOperations.subtract(dgk_public.ONE, Encrypted_Y[i], dgk_public);
			}
			else {
				XOR[i] = Encrypted_Y[i];
			}
		}

		// Step 3: Alice picks deltaA and computes s 

		// Step 4: Compute C_i
		C = new BigInteger[Encrypted_Y.length + 1];

		// Compute the Product of XOR, add s and compute x - y
		// C_i = sum(XOR) + s + x_i - y_i
		for (int i = 0; i < Encrypted_Y.length;i++) {
			C[i] = DGKOperations.multiply(DGKOperations.sum(XOR, dgk_public, i), 3, dgk_public);
			C[i] = DGKOperations.add_plaintext(C[i], 1 - 2 * delta_a, dgk_public);
			C[i] = DGKOperations.subtract(C[i], Encrypted_Y[i], dgk_public);
			C[i] = DGKOperations.add_plaintext(C[i], NTL.bit(x, i), dgk_public);
		}

		//This is c_{-1}
		C[Encrypted_Y.length] = DGKOperations.sum(XOR, dgk_public);
		C[Encrypted_Y.length] = DGKOperations.add_plaintext(C[Encrypted_Y.length], delta_a, dgk_public);

		// Step 5: Blinds C_i, Shuffle it and send to Bob
		for (int i = 0; i < C.length; i++) {
			C[i] = DGKOperations.multiply(C[i], rnd.nextInt(dgk_public.getU().intValue()) + 1, dgk_public);
		}
		C = shuffle_bits(C);
		toBob.writeObject(C);
		toBob.flush();
		// Run Extra steps to help Alice decrypt Delta
		return decrypt_protocol_one(delta_a);
	}

	protected boolean decrypt_protocol_one(int delta_a) throws IOException, ClassNotFoundException, HomomorphicException {
		Object o;
		BigInteger delta;
		BigInteger blind = BigInteger.ZERO;

		// Step 6: Bob looks for any 0's in C_i and computes DeltaB

		// Step 7: Obtain Delta B from Bob
		// Party B encrypts delta_B using his public key and sends it to Alice. Upon receiving
		// delta_B, party A computes the encryption of delta as
		// 1- delta = delta_b if delta_a = 0
		// 2- delta = 1 - delta_b otherwise if delta_a = 1.
		o = fromBob.readObject();
		if (o instanceof BigInteger) {
			if (delta_a == 0) {
				delta = (BigInteger) o;
			}
			else {
				delta = DGKOperations.subtract(dgk_public.ONE, (BigInteger) o, dgk_public);
			}
		}
		else {
			throw new HomomorphicException("Invalid Object found here: " + o.getClass().getName());
		}

		/*
		 * Step 8: Bob has the Private key anyway
		 * Send him the encrypted answer!
		 * Alice and Bob know now without revealing x or y!
		 *
		 * You can blind it for safety, but I will assume Bob is nice
		 * Plus the info doesn't really reveal anything to Bob.
		 */
		// blind = NTL.RandomBnd(dgk_public.getU());
		toBob.writeObject(DGKOperations.add_plaintext(delta, blind, dgk_public));
		toBob.flush();

		o = fromBob.readObject();
		if (o instanceof BigInteger) {
			delta = (BigInteger) o;
			delta = delta.subtract(blind);
			return delta.equals(BigInteger.ONE);
		}
		else {
			throw new HomomorphicException("Invalid Object found here: " + o.getClass().getName());
		}
	}

	protected boolean decrypt_protocol_two(BigInteger result) throws IOException {
		int comparison;
		toBob.writeObject(result);
		toBob.flush();
		comparison = fromBob.readInt();// x <= y
		// IF SOMETHING HAPPENS...GET POST MORTEM HERE
		if (comparison != 0 && comparison != 1) {
			throw new IllegalArgumentException("Invalid Comparison output! --> " + comparison);
		}
		return comparison == 1;
	}

	/**
	 * 
	 * @param x - Encrypted Paillier value OR Encrypted DGK value
	 * @param y - Encrypted Paillier value OR Encrypted DGK value
	 * @return X >= Y
	 */
	public boolean Protocol2(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException, HomomorphicException
	{
		Object bob;
		int deltaB;
		int deltaA = rnd.nextInt(2);
		int x_leq_y;
		BigInteger alpha_lt_beta;
		BigInteger z;
		BigInteger zdiv2L;
		BigInteger result;
		BigInteger r;
		BigInteger alpha;

		// Step 1: 0 <= r < N
		// Pick Number of l + 1 + sigma bits
		// Considering DGK is an option, just stick with size of Zu		
		if (isDGK) {
			throw new IllegalArgumentException("Protocol 2 is NOT allowed with DGK! Used Protocol 4!");
		}
		else
		{
			// Generate Random Number with l + 1 + sigma bits
			if (dgk_public.getL() + SIGMA + 2 < paillier_public.key_size) {
				r = NTL.generateXBitRandom(dgk_public.getL() + 1 + SIGMA);
			}
			else {
				throw new IllegalArgumentException("Invalid due to constraint: l + sigma + 2 < log_2(N)!");
			}
		}

		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		z = PaillierCipher.add_plaintext(x, r.add(powL).mod(paillier_public.getN()), paillier_public);
		z = PaillierCipher.subtract(z, y, paillier_public);
		toBob.writeObject(z);
		toBob.flush();

		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		alpha = NTL.POSMOD(r, powL);

		// Step 4: Complete Protocol 1 or Protocol 3
		boolean P3 = Protocol1(alpha);
		if(P3) {
			x_leq_y = 1;
		}
		else {
			x_leq_y = 0;
		}

		// Step 5A: get Delta B


		// Step 5A: get Delta B 
		if(deltaA == x_leq_y) {
			deltaB = 0;
		}
		else {
			deltaB = 1;
		}

		// Step 5B: Bob sends z/2^l 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger) {
			zdiv2L = (BigInteger) bob;
		}
		else {
			throw new IllegalArgumentException("Protocol 2, Step 5: z/2^l not found!");
		}

		// Step 6: Get [[beta < alpha]]
		if(deltaA == 1) {
			alpha_lt_beta = PaillierCipher.encrypt(deltaB, paillier_public);
		}
		else {
			alpha_lt_beta = PaillierCipher.encrypt(1 - deltaB, paillier_public);
		}

		// Step 7: get [[x <= y]]
		result = PaillierCipher.subtract(zdiv2L, PaillierCipher.encrypt(r.divide(powL), paillier_public), paillier_public);
		result = PaillierCipher.subtract(result, alpha_lt_beta, paillier_public);

		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob by definition would know the answer as well.
		 */
		return decrypt_protocol_two(result);
	}

	/**
	 * Please review Protocol 2 in the "Encrypted Integer Division" paper by Thjis Veugen
	 *
	 * @param x - Encrypted Paillier value or Encrypted DGK value
	 * @param d - plaintext divisor
	 * @throws IOException            - Any socket errors
	 * @throws HomomorphicException   Constraints: 0 <= x <= N * 2^{-sigma} and 0 <= d < N
	 */
	public BigInteger division(BigInteger x, long d)
			throws IOException, ClassNotFoundException,  HomomorphicException {
		Object in;
		BigInteger answer;
		BigInteger c;
		BigInteger z;
		BigInteger r;

		int t = 0;
		
		// Step 1
		if(this.isDGK) {
			r = NTL.generateXBitRandom(dgk_public.getL() - 1).mod(dgk_public.getU());
			z = DGKOperations.add_plaintext(x, r, dgk_public);
			//N = dgk_public.bigU;
		}
		else {
			r = NTL.generateXBitRandom(paillier_public.key_size - 1).mod(paillier_public.getN());
			z = PaillierCipher.add_plaintext(x, r, paillier_public);
			//N = paillier_public.n;
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Executed by Bob
		
		// Step 3: Compute secure comparison Protocol
		if(!FAST_DIVIDE) {
			if (!Protocol1(r.mod(BigInteger.valueOf(d)))) {
				t = 1;
			}
		}
		
		// Step 4: Bob computes c and Alice receives it
		in = fromBob.readObject();
		if (in instanceof BigInteger) {
			c = (BigInteger) in;
		}
		else {
			throw new IllegalArgumentException("Division: c is not found (Invalid Object): " + in.getClass().getName());
		}
		
		// Step 5: Alice computes [x/d]
		// [[z/d - r/d]]
		// [[z/d - r/d - t]]
		if (isDGK) {
			answer = DGKOperations.subtract_plaintext(c, r.divide(BigInteger.valueOf(d)), dgk_public);
			if(t == 1) {
				answer = DGKOperations.subtract_plaintext(answer, BigInteger.valueOf(t), dgk_public);
			}
		}
		else
		{
			answer = PaillierCipher.subtract_plaintext(c, r.divide(BigInteger.valueOf(d)), paillier_public);
			if(t == 1) {
				answer = PaillierCipher.subtract_plaintext(answer, BigInteger.valueOf(t), paillier_public);
			}
		}
		return answer;
	}

	public BigInteger multiplication(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException
	{
		Object in;
		BigInteger x_prime;
		BigInteger y_prime;
		BigInteger a;
		BigInteger b;
		BigInteger result;

		// Step 1
		if(isDGK) {
			a = NTL.RandomBnd(dgk_public.getU());
			b = NTL.RandomBnd(dgk_public.getU());
			x_prime = DGKOperations.add_plaintext(x, a, dgk_public);
			y_prime = DGKOperations.add_plaintext(y, b, dgk_public);
		}
		else {
			a = NTL.RandomBnd(paillier_public.getN());
			b = NTL.RandomBnd(paillier_public.getN());
			x_prime = PaillierCipher.add_plaintext(x, a, paillier_public);
			y_prime = PaillierCipher.add_plaintext(y, b, paillier_public);
		}
		// x' = x + a
		toBob.writeObject(x_prime);
		toBob.flush();

		// y' = y + b
		toBob.writeObject(y_prime);
		toBob.flush();
		
		// Step 2
		
		// Step 3
		in = fromBob.readObject();
		if (in instanceof BigInteger) {
			// (x + a)(y + b) = xy + xb + ya + ab
			// xy = (x + a)(y + b) - xb - ya - ab
			result = (BigInteger) in;
			if(isDGK) {
				result = DGKOperations.subtract(result, DGKOperations.multiply(x, b, dgk_public), dgk_public);
				result = DGKOperations.subtract(result, DGKOperations.multiply(y, a, dgk_public), dgk_public);
				// To avoid throwing an exception to myself of encrypt range [0, U), mod it now!
				result = DGKOperations.subtract_plaintext(result, a.multiply(b).mod(dgk_public.getU()), dgk_public);
			}
			else {
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(x, b, paillier_public), paillier_public);
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(y, a, paillier_public), paillier_public);
				// To avoid throwing an exception to myself of encrypt range [0, N), mod it now!
				result = PaillierCipher.subtract_plaintext(result, a.multiply(b).mod(paillier_public.getN()), paillier_public);
			}
		}
		else {
			throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob: " + in.getClass().getName());
		}
		return result;
	}

	public void receivePublicKeys()
			throws IOException, ClassNotFoundException {
		Object x;
		x = fromBob.readObject();
		if (x instanceof DGKPublicKey) {
			System.out.println("Alice Received DGK Public key from Bob");
			this.setDGKPublicKey((DGKPublicKey) x);
		}
		else {
			dgk_public = null;
		}
		
		x = fromBob.readObject();
		if(x instanceof PaillierPublicKey) {
			System.out.println("Alice Received Paillier Public key from Bob");
			this.setPaillierPublicKey((PaillierPublicKey) x);
		}
		else {
			paillier_public = null;
		}
	
		x = fromBob.readObject();
		if(x instanceof ElGamalPublicKey) {
			System.out.println("Alice Received ElGamal Public key from Bob");
			this.setElGamalPublicKey((ElGamalPublicKey) x);
		}
		else {
			el_gamal_public = null;
		}
	}
	

	// Use Bubble sort to get K-biggest or smallest values. You can sort the whole list too if you want
	public BigInteger[] getKValues(BigInteger [] input, int k, boolean smallest_first)
			throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException
	{
		if(k > input.length || k <= 0) {
			throw new IllegalArgumentException("Invalid k value! " + k);
		}
		BigInteger [] arr = deep_copy(input);
		BigInteger [] sorted_k = new BigInteger[k];
		
		boolean activation;
		for (int i = 0; i < k; i++) {
			for (int j = 0; j < arr.length - 1 - i; j++) {
				toBob.writeBoolean(true);
				toBob.flush();
				// Might need a K-Max test as well!
				activation = this.Protocol2(arr[j], arr[j + 1]);
				if (smallest_first) {
					activation = !activation;
				}
				
				// Originally arr[j] > arr[j + 1]
				if (activation) {
					// swap temp and arr[i]
					BigInteger temp = arr[j];
					arr[j] = arr[j + 1];
					arr[j + 1] = temp;
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++) {
			if (smallest_first) {
				sorted_k[i] = arr[arr.length - 1 - i];
			}
			else {
				sorted_k[k - 1 - i] = arr[arr.length - 1 - i];
			}
		}
		
		// Close Bob
		toBob.writeBoolean(false);
		toBob.flush();
		return sorted_k;
	}
	
	public BigInteger[] getKValues(List<BigInteger> input, int k,  boolean smallest_first)
			throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException
	{
		if(k > input.size() || k <= 0) {
			throw new IllegalArgumentException("Invalid k value!");
		}
		// deep copy
		List<BigInteger> arr = new ArrayList<>(input);
		
		BigInteger [] sorted_k = new BigInteger[k];
		
		boolean activation;
		for (int i = 0; i < k; i++) {
			for (int j = 0; j < arr.size() - i - 1; j++) {
				toBob.writeBoolean(true);
				toBob.flush();
				activation = this.Protocol2(arr.get(j), arr.get(j + 1));

				if(smallest_first) {
					activation = !activation;
				}
				
				// Originally arr[j] > arr[j + 1]
				if (activation) {
					// swap temp and arr[i]
					BigInteger temp = arr.get(j);
					arr.set(j, arr.get(j + 1));
					arr.set(j + 1, temp);
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++) {
			if (smallest_first) {
				sorted_k[i] = arr.get(arr.size() - 1 - i);
			}
			else {
				sorted_k[k - 1 - i] = arr.get(arr.size() - 1 - i);
			}
		}
		
		// Close Bob
		toBob.writeBoolean(false);
		toBob.flush();
		return sorted_k;
	}
}
