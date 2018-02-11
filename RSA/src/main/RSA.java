package main;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	final static BigInteger e = new BigInteger("65537");
	final static BigInteger bigOne = new BigInteger("1");
	private static BigInteger p;
	private static BigInteger q;
	private static BigInteger phiN;
	private static BigInteger n;
	private static long startTime;
	private static long endTime;
	private static long runningTime;

	public static void main(String[] args) {
		p = findPrime("p|q");
		q = findPrime("p|q");
		
		phiN = calculatePhiN(p, q);
		
		n = p.multiply(q);
		
		System.out.println("Performing invariant checks...\n");
		invariantChecks(p, q, n, phiN);
		
		BigInteger d = e.modInverse(phiN);
		BigInteger m = createMessage();
		
		while (m.gcd(n).compareTo(bigOne) != 0) {
			System.out.println("m and n are NOT coprime! Regenerating values...\n");
			invariantChecks(p, q, n, phiN);
			d = e.modInverse(phiN);
			m = createMessage();
		}
		System.out.println("m and n are coprime!\n");
		
		System.out.println("All values are valid. Encrypting the message...\n");
		BigInteger c = encrypt(m);
		System.out.println("Value of m (message): " + m + "\n" + "Value of c (ciphertext): " + c + "\n");
		
		System.out.println("Decrypting...\n");
		BigInteger newM = decrypt(c,d);
		
		if (newM.compareTo(m) == 0) System.out.print("Decrypted message is equal to original message! Success!\n");
		else System.out.println("Decrypted message is not equal to original message\n");
		
		System.out.println("old m: " + m + "\n" + "new m: " + newM + "\n");
	}
	
	/*
	 * Utilizes four different boolean values to check invariants; check1, check2, check3 and check 4. These invariants include 
	 * p and q's bit lengths (check1), difference between p and q (check2), bit length of n (check3) and whether or not phi N is 
	 * coprime with e (check4). If all four of these booleans are true, then the invariants are satisfied and the method returns.
	 * Otherwise p,q, n and phiN are regenerated and the values are re-checked.
	 */
	private static void invariantChecks(BigInteger p, BigInteger q, BigInteger n, BigInteger phiN) {
		boolean valid = false;
		boolean check1 = false;
		boolean check2 = false;
		boolean check3 = false;
		boolean check4 = false;
		BigInteger big2 = new BigInteger("2");
		int exponent = 1000;
		while (!valid) {
			BigInteger check = big2.pow(exponent);
			BigInteger difference = p.subtract(q).abs();
			// Invariant 1: Are p and q's bit lengths over 1536?
			if (p.bitLength() >= 1536 && q.bitLength() >= 1536) check1 = true;
			else System.out.println("p or q bit length not right!\n");
			// Invariant 2: Is the difference between p and q greater than 2^1000?
			if (difference.compareTo(check) > 0) check2 = true;
			else System.out.println("Difference between p and q less than 2^1000!\n");
			// Invariant 3: Is the bit length of n at least 3072?
			if (n.bitLength() >= 3072) check3 = true;
			else System.out.println("n bit length less than 3072!\n");
			// Invariant 4: Is phi N coprime with e?
			if (phiN.gcd(e).compareTo(bigOne) == 0) check4 = true;
			else System.out.println("phi N not coprime with e!\n");
			// If all invariants are satisfied, report success and return
			if (check1 && check2 && check3 && check4) valid = true;
			if (!valid) {
				System.out.println("Invariants not all satisfied. Regenerating p and q...\n");
				p = findPrime("p|q");
				q = findPrime("p|q");
				n = p.multiply(q);
				phiN = calculatePhiN(p, q);
			}
		}
		System.out.println("Bit length of p: " + p.bitLength() + "\n");
		System.out.println("Bit length of q: " + q.bitLength() + "\n");
		
		System.out.println("Is difference between p and q greater than 2^1000? ");
		if (check2) System.out.println("Yes\n");
		else System.out.println("No\n");
		
		System.out.println("Bit length of n: " + n.bitLength() + "\n");
		
		System.out.println("Is the GCD between phi N and e = 1? ");
		if (check3) System.out.println("Yes\n");
		else System.out.println("No\n");
	}
	
	/*
	 *  Calculates and returns a probable BigInteger prime number with 1536 bits
	 */
	private static BigInteger findPrime(String input) {
		BigInteger ret;
		SecureRandom rand = new SecureRandom();
		byte bytes[] = new byte[384];
		rand.nextBytes(bytes);
		if (input.equals("p|q")) ret = BigInteger.probablePrime(1536, rand);
		else ret = BigInteger.probablePrime(3000, rand);
		return ret;
	}
	
	/*
	 * Creates a phi N by subtracting 1 from p and q then multiplying
	 */
	private static BigInteger calculatePhiN(BigInteger p, BigInteger q) {
		BigInteger psub1 = p.subtract(bigOne);
		BigInteger qsub1 = q.subtract(bigOne);
		return psub1.multiply(qsub1);
	}
	
	/*
	 * Creates a new message BigInteger with the findPrime method. Checks that message
	 * is coprime with N
	 */
	private static BigInteger createMessage() {
		BigInteger message = findPrime("M");
		while (n.gcd(message).compareTo(bigOne) != 0) {
			System.out.println("GCD of N and message are not coprime! Creating new n");
			message = findPrime("M");
		}
		return message;
	}
	
	/*
	 * Encrypts the message value m and returns the ciphertext c
	 */
	
	private static BigInteger encrypt(BigInteger m) {
		startTime = System.currentTimeMillis();
		BigInteger c = m.modPow(e, n);
		endTime = System.currentTimeMillis();
		runningTime = endTime - startTime;
		System.out.println("Encrypting time (ms) = " + runningTime + "\n");
		return c;
	}
	
	/*
	 * Decrypts the ciphertext c and returns the new message value newM
	 */
	private static BigInteger decrypt(BigInteger c, BigInteger d) {
		startTime = System.currentTimeMillis();
		BigInteger newM = c.modPow(d, n);
		endTime = System.currentTimeMillis();
		runningTime = endTime - startTime;
		System.out.println("Decrypting time (ms) = " + runningTime + "\n");
		return newM;
	}
}
