package de.mtg.jplants;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class MerkleTreeTest {


    @Test
    void computeRoot() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] first = "first".getBytes();
        byte[] second = "second".getBytes();
        byte[] third = "third".getBytes();
        byte[] fourth = "fourth".getBytes();
        byte[] fifth = "fifth".getBytes();
        List<byte[]> entries = Arrays.asList(first, second, third, fourth, fifth);
        MerkleTree merkleTree = new MerkleTree(0, 5, entries);

        byte[] root = null;
        try {
            root = merkleTree.rootHash();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        assertNotNull(root);
        System.out.println(Hex.toHexString(root));

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);

        messageDigest.update((byte) 0x00);
        messageDigest.update(first);
        byte[] leaf1 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(second);
        byte[] leaf2 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(third);
        byte[] leaf3 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(fourth);
        byte[] leaf4 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(fifth);
        byte[] leaf5 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(leaf1);
        messageDigest.update(leaf2);
        byte[] node12 =  messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(leaf3);
        messageDigest.update(leaf4);
        byte[] node34 =  messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(node12);
        messageDigest.update(node34);
        byte[] node14 =  messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(node14);
        messageDigest.update(leaf5);
        byte[] node15 =  messageDigest.digest();
        messageDigest.reset();

        System.out.println(Hex.toHexString(node15));


        assertArrayEquals(node15, root);


    }

}
