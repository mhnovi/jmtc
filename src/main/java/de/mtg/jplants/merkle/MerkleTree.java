package de.mtg.jplants.merkle;

import de.mtg.jplants.utils.TreeUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class MerkleTree {

    private final MerkleHasher hasher;

    /**
     * The frontier: one hash per set bit in the current size,
     * ordered from least significant to most significant bit.
     * frontier.get(i) is the hash of the complete subtree of size 2^i
     * covering the most recent 2^i entries.
     */
    private final List<byte[]> frontier = new ArrayList<>();

    /**
     * Full node store: every internal node hash ever computed,
     * keyed by (level, position) for proof construction.
     * level 0 = leaves, level k = subtrees of size 2^k.
     */
    private final Map<NodeKey, byte[]> nodes = new HashMap<>();

    private long size = 0;


    MerkleTree(){
        // With default MerkleHasher
        this.hasher = new MerkleHasher();
    }
    MerkleTree(MerkleHasher hasher) {

        this.hasher = hasher;
    }

    void append(List<byte[]> entriesBatch) {
        // TODO
        if(size == 0){
            // TODO or Batch Null
        }
        long batchSize = entriesBatch.size();
        long newSize =  size + batchSize;
        long last = size - 1;

        for(byte[] entry : entriesBatch){
            appendEntry(entry,last);
        }

        // if newSize is not power of 2 -> root is not recomputed
        // if any leaf is "dangling" at the end, take it into account and propagate to root
        // todos los sobrantes hasta el proximo power of 2
        // agarrar todos los sobrantes y conectarlos sobrantes son right edge, right sibling of every full subtree
        if(!TreeUtils.isPowerOfTwo(newSize)){
            // TODO use frontier
        }

        //Update size
        size = newSize;
    }

    // Doesn't take into account when the leaf is alone. Try [0,6) -> append at pos=6
    // only propagates upwards if there is already a left sibling, if not waits and leave the leaf "dangling"
    private void appendEntry(byte[] rawEntry, long last){
        long level = 0;
        long pos = last + 1;
        //Store leaf
        byte[] hash = hasher.leafHash(rawEntry);
        storeNode(level, pos, hash);
        //Merge upwards
        while(TreeUtils.isLSBSet(pos)){
            byte[] leftSiblingHash = nodes.get(new NodeKey(level, pos ^ 1));
            hash = hasher.nodeHash(leftSiblingHash, hash);
            level++;
            pos = pos >> 1;
            nodes.put(new NodeKey(level, pos), hash);
        }
    }

    /**
     *
     * @param level
     * @param position
     * @param nodeHashValue
     */
    void storeNode(long level, long position, byte[] nodeHashValue){
        NodeKey nodeKey = new NodeKey(level, position);
        nodes.put(nodeKey,nodeHashValue);
    }

    public long getSize() {
        return size;
    }

}
