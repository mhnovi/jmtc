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
    private List<byte[]> entries;

    MerkleTree(int start, int end, List<byte[]> entries) {
        this.start = start;
        this.end = end;
        this.entries = entries;
    }

    void append() {
        // TODO
    }

    // MTH(D_n) as defined in RFC9162 Section 2.1.1
    byte[] rootHash() throws NoSuchAlgorithmException, NoSuchProviderException {
        return subTreeHash(start, end);
    }

    // [start, end)
    // k < n <= 2k  k is the largest power of 2 smaller than n
    byte[] subTreeHash(int start, int end) throws NoSuchAlgorithmException, NoSuchProviderException {
        int size = end - start;

        if (size == 1) {
            return leafHash(entries.get(start));
        }
        if (size <= 0) {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME); // For now only SHA-256
            messageDigest.update((byte[]) null); // TODO correct?
            return messageDigest.digest();
        }

        // compute split index k
        int splitK = start + largestPowerOfTwoSmallerThan(size);

        return internalHash(subTreeHash(start, splitK), subTreeHash(splitK, end));
    }

    byte[] leafHash(byte[] entry) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
        messageDigest.update((byte) 0x00);
        messageDigest.update(entry);
        return messageDigest.digest();
    }

    byte[] internalHash(byte[] left, byte[] right) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
        messageDigest.update((byte) 0x01);
        messageDigest.update(left);
        messageDigest.update(right);
        return messageDigest.digest();
    }

    int largestPowerOfTwoSmallerThan(int n) {
        int highestOneBit = Integer.highestOneBit(n);
        if (highestOneBit == n) {
            return n / 2;
        }
        return highestOneBit;
    }

    public int getSize() {
        return end - start;
    }

    public byte[] getRootHash() {
        return rootHash;
    }

    public int getStart() {
        return start;
    }

    public int getEnd() {
        return end;
    }

    public List<byte[]> getEntries() {
        return entries;
    }
}
