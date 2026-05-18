package de.mtg.jplants.merkle;

import de.mtg.jplants.utils.TreeUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

public class MerkleHasher {

    private final String hashingAlgorithm;
    private final String provider;
    private final MessageDigest messageDigest;

    // Default hashing algorithm specified in the Merkle Tree Certificates internet draft
    MerkleHasher(){
        this.hashingAlgorithm = "SHA-256";
        this.provider = BouncyCastleProvider.PROVIDER_NAME;
        try{
            this.messageDigest = MessageDigest.getInstance(hashingAlgorithm, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e){
            throw new IllegalArgumentException(e);
        }

    }

    MerkleHasher(String hashingAlgorithm, String provider){
        this.hashingAlgorithm = hashingAlgorithm;
        this.provider = provider;
        try{
            this.messageDigest = MessageDigest.getInstance(hashingAlgorithm, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e){
            throw new IllegalArgumentException(e);
        }
    }


    /**
     * MTH(D_n) as defined in RFC9162 Section 2.1.1
     * @param entries List contaaining the all the entries of the merkle tree
     * @return the Merkle tree root hash
     */
    byte[] mth(List<byte[]> entries) {
        int size = entries.size();

        if (size == 0) {
            String emptyString = "";
            messageDigest.update(emptyString.getBytes());
            return messageDigest.digest();
        }

        if (size == 1) {
            return leafHash(entries.get(0));
        }

        // compute split position k
        int splitK = TreeUtils.largestPowerOfTwoSmallerThan(size);

        byte[] left = mth(entries.subList(0, splitK));
        byte[] right = mth(entries.subList(splitK, size));

        return nodeHash(left,right);
    }

    /**
     * computes the hash value of the root of the subtree [start, end)
     * TODO check if it needs the FULL entries list or can it be a subset ??
     * @param start Start of subtree
     * @param end End of subtree
     * @param entries FULL list of Merkle tree entries
     * @return Root hash of subtree
     */
    byte[] subTreeHash(int start, int end, List<byte[]> entries) {
        int size = end - start;

        if (size == 1) {
            return leafHash(entries.get(start));
        }
        if (size <= 0) {
            String emptyString = "";
            messageDigest.update(emptyString.getBytes());
            return messageDigest.digest();
        }

        // compute split position k
        // k < n <= 2k  k is the largest power of 2 smaller than n
        int splitK = start + TreeUtils.largestPowerOfTwoSmallerThan(size);

        byte[] left = subTreeHash(start, splitK, entries);
        byte[] right = subTreeHash(splitK, end, entries);

        return nodeHash(left,right);
    }

    /**
     * Computes the hash value of the given entry.
     * @param entry Raw entry
     * @return Has value of leaf
     */
    public byte[] leafHash(byte[] entry)  {
        if(entry == null || entry.length == 0){
            throw new IllegalArgumentException("The entry must not be null or empty");
        }
        byte[] leafHash;
        messageDigest.update((byte) 0x00);
        messageDigest.update(entry);
        leafHash = messageDigest.digest();
        return leafHash;
    }

    /**
     * Computes the hash value of the node digesting the hash values of its left and right child
     * @param left Left child
     * @param right Right child
     * @return Hash value of the corresponding node
     */
    public byte[] nodeHash(byte[] left, byte[] right) {
        if(left == null || left.length == 0 || right == null || right.length == 0){
            throw new IllegalArgumentException("Both child nodes must not be null or empty");
        }
        byte[] internalHash;
        messageDigest.update((byte) 0x01);
        messageDigest.update(left);
        messageDigest.update(right);
        internalHash = messageDigest.digest();
        return internalHash;
    }

}
