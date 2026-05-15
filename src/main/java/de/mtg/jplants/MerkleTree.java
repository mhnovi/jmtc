package de.mtg.jplants;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MerkleTree {
    private int start;
    private int end;
    private byte[] rootHash;
    private List<byte[]> hasehdEntries;
    private String hashAlgorithm =  "SHA-256"; // For now only SHA-256

    MerkleTree(int start, int end, List<byte[]> hasehdEntries) {
        this.start = start;
        this.end = end;
        this.hasehdEntries = hasehdEntries;
        this.rootHash = subTreeHash(start, end);
    }

    void appendSingleEntry(byte[] entry) {
        // TODO
    }
    void appendBatch(List<byte[]> entries) {
        // TODO
        // batches ?
        // see how many nodes until full with BIT_CEIL ?
        // insert in stack after every new full subtree?
        // add to end + entries.size
    }

    // MTH(D_n) as defined in RFC9162 Section 2.1.1
    byte[] rootHash() {
        return subTreeHash(start, end);
    }

    // [start, end)
    // k < n <= 2k  k is the largest power of 2 smaller than n
    byte[] subTreeHash(int start, int end) {
        int size = end - start;

        if (size == 1) {
            return leafHash(hasehdEntries.get(start));
        }
        if (size <= 0) {
            try{
                MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
                messageDigest.update((byte[]) null); // TODO correct see Draft?
                return messageDigest.digest();
            } catch (NoSuchAlgorithmException | NoSuchProviderException e){
                throw new RuntimeException(e);
            }
        }

        // compute split index k
        int splitK = start + largestPowerOfTwoSmallerThan(size);

        return internalHash(subTreeHash(start, splitK), subTreeHash(splitK, end));
    }

    byte[] leafHash(byte[] entry)  {
        byte[] leafHash; // TODO better null handling?
        try{
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            messageDigest.update((byte) 0x00);
            messageDigest.update(entry);
            leafHash = messageDigest.digest();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e){
            throw new RuntimeException(e);
        }

        return leafHash;
    }

    byte[] internalHash(byte[] left, byte[] right) {
        byte[] internalHash; // TODO better null handling?
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            messageDigest.update((byte) 0x01);
            messageDigest.update(left);
            messageDigest.update(right);
            internalHash = messageDigest.digest();
        }  catch (NoSuchAlgorithmException | NoSuchProviderException e){
            throw new RuntimeException(e);
        }
        return internalHash;
    }

    boolean isValidSubtree() {
        long size = end - start;
        long bitCeil = bitCeil(size);
        return start % bitCeil == 0;
    }

    // If is not full is partial
    boolean isFullSubtree() {
        return Long.bitCount(end - start) == 1;
    }

    int largestPowerOfTwoSmallerThan(int n) {
        int highestOneBit = Integer.highestOneBit(n);
        if (highestOneBit == n) {
            return n / 2;
        }
        return highestOneBit;
    }

    //Smallest power of 2 greater or equal than n
    long bitCeil(long n){
        if(n <= 1){
            return 1;
        }
        return Long.highestOneBit(n) << (Long.bitCount(n) > 1 ? 1 : 0);
    }

    public int getSize() {
        return end - start;
    }

    public byte[] getCurrentRootHash() {
        return rootHash;
    }

    public int getStart() {
        return start;
    }

    public int getEnd() {
        return end;
    }

    public List<byte[]> getHasehdEntries() {
        return hasehdEntries;
    }
}
