package de.mtg.jplants.merkle;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

import de.mtg.jplants.utils.TreeUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MerkleTree {
    private int start;
    private int end;
    private byte[] rootHash;
    private List<byte[]> hasehdEntries;
    private String hashAlgorithm =  "SHA-256"; // For now only SHA-256

    MerkleTree(int start, int end, List<byte[]> hashedEntries) {
        this.start = start;
        this.end = end;
        this.hasehdEntries = hashedEntries;
        this.rootHash = subTreeHash(start, end);
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
        int splitK = start + TreeUtils.largestPowerOfTwoSmallerThan(size);

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

    public List<byte[]> getHashedEntries() {
        return hasehdEntries;
    }
}
