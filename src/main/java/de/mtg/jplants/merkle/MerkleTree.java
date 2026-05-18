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

    // With default MerkleHasher
    MerkleTree(){
        this.hasher = new MerkleHasher();
    }
    MerkleTree(MerkleHasher hasher) {
        this.hasher = hasher;
    }

    void append(List<byte[]> entriesBatch) {
        // TODO
        long batchSize = entriesBatch.size();
        long newSize =  size + batchSize;
        long last = size - 1;

        // 1. Proof if last index is full or partial subtree
        if(!TreeUtils.isPowerOfTwo(size)){
            // 1.1 true -> Append necessary entries (or single) to make a full little tree. With BIT_CEIL?
            // +1 because of single append
            last ++;
        }

        // 3. Get new last index and merge hashes from new last index backwards to old last index
        long newLast = newSize - 1;


        // 4. Increase new size
        size += batchSize;
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
