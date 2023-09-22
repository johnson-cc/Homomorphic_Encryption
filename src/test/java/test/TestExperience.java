package test;

import org.apache.lucene.util.RamUsageEstimator;
import org.springframework.util.StopWatch;
import org.junit.BeforeClass;
import org.junit.Test;
import security.dgk.DGKKeyPairGenerator;
import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.misc.HomomorphicException;
import security.misc.NTL;


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class TestExperience implements constants{
    private static DGKPublicKey public_key;
    private static DGKPrivateKey private_key;
    protected static final SecureRandom rnd = new SecureRandom();

    public static int SLEEPTIME = 10;
    private static BigInteger a;

    @BeforeClass
    public static void generate_keys() {
        DGKKeyPairGenerator pa = new DGKKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair dgk = pa.generateKeyPair();
        public_key = (DGKPublicKey) dgk.getPublic();
        private_key = (DGKPrivateKey) dgk.getPrivate();

    }
    @Test
    public void test_compare() throws Exception {
        String path = "E:\\GitHub\\STDA\\ECG200\\FunctionTest.csv";
        CsvDemo csvDemo = new CsvDemo(path);
        ArrayList<List<Integer>> data = csvDemo.readCSV();
        for (int k =0;k<21;k=k+2){
            for (int j =0;j<96;j++)
            {
                BigInteger x =new BigInteger(String.valueOf(data.get(k).get(j)));
                BigInteger y =new BigInteger(String.valueOf(data.get(k+1).get(j)));
                StopWatch stopwatch = new StopWatch("test_compare");
                //Step 1: Bob sends encrypted bits to Alice
                BigInteger [] EncY = new BigInteger[y.bitLength()];
                for (int i = 0; i < y.bitLength(); i++) {
                    EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), public_key);
                }
                stopwatch.start("compare_Enc");
                boolean result1 = compare(x,y,EncY);
                stopwatch.stop();
                System.out.println("result is: " + result1);
//                stopwatch.start("compare_Plaintext");
//                boolean result = compare(x,y);
//                stopwatch.stop();
//                System.out.println("result is: " + result);
                System.out.println(stopwatch.prettyPrint());
            }
        }
//        BigInteger x =  new BigInteger(String.valueOf(data.get(0).get(0)));
//        BigInteger y =  new BigInteger(String.valueOf(data.get(0).get(1)));
//        BigInteger x = new BigInteger("1240");
//        BigInteger y = new BigInteger("1239");
//        StopWatch stopwatch = new StopWatch("test_compare");
//        //Step 1: Bob sends encrypted bits to Alice
//        BigInteger [] EncY = new BigInteger[y.bitLength()];
//        for (int i = 0; i < y.bitLength(); i++) {
//            EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), public_key);
//        }
//        stopwatch.start("compare_Enc");
//        boolean result1 = compare(x,y,EncY);
//        stopwatch.stop();
//        System.out.println("result is: " + result1);
//
//        stopwatch.start("compare_Plaintext");
//        boolean result = compare(x,y);
//        stopwatch.stop();
//        System.out.println("result is: " + result);
//        System.out.println(stopwatch.prettyPrint());
    }
    public boolean compare(BigInteger x,BigInteger y,BigInteger[] EncY) throws HomomorphicException {
        // Constraint...
//        if(x.bitLength() > public_key.getL()) {
//            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
//        }
//        if(y.bitLength() > public_key.getL()) {
//            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, y is: " + y.bitLength() + " bits");
//        }
        //Step 1: Bob sends encrypted bits to Alice
//        BigInteger [] EncY = new BigInteger[y.bitLength()];
//        for (int i = 0; i < y.bitLength(); i++) {
//            EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), public_key);
//        }
        //通信量

        long communication = 0;
        //Alice Get Y bits from Bob
            sleep();

            for (int i = 0; i < EncY.length; i++) {
                communication += RamUsageEstimator.shallowSizeOf(EncY[i]);
            }


        if (x.bitLength() < EncY.length) {
            System.out.println("Shouldn't be here: x <= y bits");
            System.out.println("communication is: " + communication);
            return true;
        }
        else if(x.bitLength() > EncY.length) {
            System.out.println("Shouldn	't be here: x > y bits");
            System.out.println("communication is: " + communication);
            return false;
        }
        // Otherwise, if the bit size is equal, proceed!
        // Step 2: compute Encrypted X XOR Y
        BigInteger [] XOR;
        XOR = new BigInteger[EncY.length];
        for (int i = 0; i < EncY.length; i++)
        {
            if (NTL.bit(x, i) == 1) {
                XOR[i] = DGKOperations.subtract(public_key.ONE, EncY[i], public_key);
            }
            else {
                XOR[i] = EncY[i];
            }
        }
        // Step 3: Alice picks deltaA and computes s
        int delta_a = rnd.nextInt(2);
        // Step 4: Compute C_i
        BigInteger [] C;
        C = new BigInteger[EncY.length + 1];
        // Compute the Product of XOR, add s and compute x - y
        // C_i = sum(XOR) + s + x_i - y_i
        for (int i = 0; i < EncY.length;i++) {
            C[i] = DGKOperations.multiply(DGKOperations.sum(XOR, public_key, i), 3, public_key);
            C[i] = DGKOperations.add_plaintext(C[i], 1 - 2 * delta_a, public_key);
            C[i] = DGKOperations.subtract(C[i], EncY[i], public_key);
            C[i] = DGKOperations.add_plaintext(C[i], NTL.bit(x, i), public_key);
        }
        //This is c_{-1}
        C[EncY.length] = DGKOperations.sum(XOR, public_key);
        C[EncY.length] = DGKOperations.add_plaintext(C[EncY.length], delta_a, public_key);
        // Step 5: Blinds C_i, Shuffle it and send to Bob
        for (int i = 0; i < C.length; i++) {
            C[i] = DGKOperations.multiply(C[i], rnd.nextInt(public_key.getU().intValue()) + 1, public_key);
        }
        C = shuffle_bits(C);

        communication += RamUsageEstimator.shallowSizeOf(C);

        sleep();
        // Step 6: Check if one of the numbers in C_i is decrypted to 0.
        int deltaB = 0;
        for (BigInteger C_i: C) {
            if (DGKOperations.decrypt(C_i, private_key) == 0) {
                deltaB = 1;
                break;
            }
        }
        // Step 7: Bob sends deltaB to Alice

        communication += RamUsageEstimator.shallowSizeOf(deltaB);

        sleep();
        BigInteger EncDeltaB = DGKOperations.encrypt(deltaB, public_key);
        BigInteger delta;
        if (delta_a == 0) {
            delta = EncDeltaB;
        }
        else {
            delta = DGKOperations.subtract(public_key.ONE, EncDeltaB, public_key);
        }
        //Step 8: Alice sent delta to Bob

        communication += RamUsageEstimator.shallowSizeOf(delta);
        sleep();
        BigInteger blind = BigInteger.ZERO;
        // blind = NTL.RandomBnd(dgk_public.getU());
        BigInteger EncDeltaA = DGKOperations.add_plaintext(delta, blind, public_key);
        BigInteger delta4B = BigInteger.valueOf(DGKOperations.decrypt(EncDeltaA, private_key));
        //Step 9: Bob decrypts delta and sent to Alice
        delta = delta4B.subtract(blind);
        //Step 10: Alice decrypts delta

        System.out.println("communication is: " + communication);
        return delta.equals(BigInteger.ONE);
    }

    //测试比较算法
    //return X <= Y
    public boolean compare(BigInteger x,BigInteger y) throws HomomorphicException {
        // Constraint...
        if(x.bitLength() > public_key.getL()) {
            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
        }
        if(y.bitLength() > public_key.getL()) {
            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, y is: " + y.bitLength() + " bits");
        }
        //Step 1: Bob sends encrypted bits to Alice
        BigInteger [] EncY = new BigInteger[y.bitLength()];
        for (int i = 0; i < y.bitLength(); i++) {
            EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), public_key);
        }
        //Alice Get Y bits from Bob
        if (x.bitLength() < EncY.length) {
            System.out.println("Shouldn't be here: x <= y bits");
            return true;
        }
        else if(x.bitLength() > EncY.length) {
            System.out.println("Shouldn	't be here: x > y bits");
            return false;
        }

        // Otherwise, if the bit size is equal, proceed!
        // Step 2: compute Encrypted X XOR Y
        BigInteger [] XOR;
        XOR = new BigInteger[EncY.length];
        for (int i = 0; i < EncY.length; i++)
        {
            if (NTL.bit(x, i) == 1) {
                XOR[i] = DGKOperations.subtract(public_key.ONE, EncY[i], public_key);
            }
            else {
                XOR[i] = EncY[i];
            }
        }
        // Step 3: Alice picks deltaA and computes s
        int delta_a = rnd.nextInt(2);
        // Step 4: Compute C_i
        BigInteger [] C;
        C = new BigInteger[EncY.length + 1];
        // Compute the Product of XOR, add s and compute x - y
        // C_i = sum(XOR) + s + x_i - y_i
        for (int i = 0; i < EncY.length;i++) {
            C[i] = DGKOperations.multiply(DGKOperations.sum(XOR, public_key, i), 3, public_key);
            C[i] = DGKOperations.add_plaintext(C[i], 1 - 2 * delta_a, public_key);
            C[i] = DGKOperations.subtract(C[i], EncY[i], public_key);
            C[i] = DGKOperations.add_plaintext(C[i], NTL.bit(x, i), public_key);
        }
        //This is c_{-1}
        C[EncY.length] = DGKOperations.sum(XOR, public_key);
        C[EncY.length] = DGKOperations.add_plaintext(C[EncY.length], delta_a, public_key);
        // Step 5: Blinds C_i, Shuffle it and send to Bob
        for (int i = 0; i < C.length; i++) {
            C[i] = DGKOperations.multiply(C[i], rnd.nextInt(public_key.getU().intValue()) + 1, public_key);
        }
        C = shuffle_bits(C);
        // Step 6: Check if one of the numbers in C_i is decrypted to 0.
        int deltaB = 0;
        for (BigInteger C_i: C) {
            if (DGKOperations.decrypt(C_i, private_key) == 0) {
                deltaB = 1;
                break;
            }
        }
        // Step 7: Bob sends deltaB to Alice
        BigInteger EncDeltaB = DGKOperations.encrypt(deltaB, public_key);
        BigInteger delta;
        if (delta_a == 0) {
            delta = EncDeltaB;
        }
        else {
            delta = DGKOperations.subtract(public_key.ONE, EncDeltaB, public_key);
        }
        //Step 8: Alice sent delta to Bob
        BigInteger blind = BigInteger.ZERO;
        // blind = NTL.RandomBnd(dgk_public.getU());
        BigInteger EncDeltaA = DGKOperations.add_plaintext(delta, blind, public_key);
        BigInteger delta4B = BigInteger.valueOf(DGKOperations.decrypt(EncDeltaA, private_key));
        //Step 9: Bob decrypts delta and sent to Alice
        delta = delta4B.subtract(blind);
        //Step 10: Alice decrypts delta
        return delta.equals(BigInteger.ONE);
    }

    protected BigInteger[] shuffle_bits(BigInteger[] array) {
        for (int i = 0; i < array.length; i++) {
            int randomPosition = rnd.nextInt(array.length);
            BigInteger temp = array[i];
            array[i] = array[randomPosition];
            array[randomPosition] = temp;
        }
        return array;
    }
    public static void sleep(){
        try {
            Thread.sleep(SLEEPTIME);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }


}
