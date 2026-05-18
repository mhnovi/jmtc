package de.mtg.jplants.merkle;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class MerkleHasherTest {

    // TODO do it systematically
    @Test
    void computeRootAndSubtrees() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] first = "first".getBytes();
        byte[] second = "second".getBytes();
        byte[] third = "third".getBytes();
        byte[] fourth = "fourth".getBytes();
        byte[] fifth = "fifth".getBytes();
        List<byte[]> entries = Arrays.asList(first, second, third, fourth, fifth);
        MerkleHasher hasher = new MerkleHasher();

        byte[] root = hasher.mth(entries);
        assertNotNull(root);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);

        messageDigest.update((byte) 0x00);
        messageDigest.update(first);
        byte[] leaf0 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(second);
        byte[] leaf1 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(third);
        byte[] leaf2 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(fourth);
        byte[] leaf3 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(fifth);
        byte[] leaf4 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(leaf0);
        messageDigest.update(leaf1);
        byte[] node01 =  messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(leaf2);
        messageDigest.update(leaf3);
        byte[] node23 =  messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(node01);
        messageDigest.update(node23);
        byte[] node03 =  messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(node03);
        messageDigest.update(leaf4);
        byte[] node04 =  messageDigest.digest();
        messageDigest.reset();

        assertArrayEquals(node04, root);
        assertArrayEquals(node03, hasher.subTreeHash(0,4, entries));
        assertArrayEquals(node23, hasher.subTreeHash(2,4, entries));
        assertArrayEquals(leaf0, hasher.subTreeHash(0,1, entries));


    }

    @Test
    void leafAndNodesTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
        byte[] first = "first".getBytes();
        byte[] second = "second".getBytes();

        messageDigest.update((byte) 0x00);
        messageDigest.update(first);
        byte[] leaf0 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x00);
        messageDigest.update(second);
        byte[] leaf1 = messageDigest.digest();
        messageDigest.reset();

        messageDigest.update((byte) 0x01);
        messageDigest.update(leaf0);
        messageDigest.update(leaf1);
        byte[] node01 = messageDigest.digest();
        messageDigest.reset();

        MerkleHasher hasher = new MerkleHasher();

        byte[] testLeaf = hasher.leafHash(first);
        assertNotNull(testLeaf);
        assertArrayEquals(leaf0, testLeaf);

        byte[] testNode = hasher.nodeHash(leaf0,leaf1);
        assertNotNull(testNode);
        assertArrayEquals(node01, testNode);

        {
            assertThrows(IllegalArgumentException.class, () -> hasher.leafHash(null));

            assertThrows(IllegalArgumentException.class, () -> hasher.nodeHash(null, null));
        }

    }
}
