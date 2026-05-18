package de.mtg.jplants.utils;

public class TreeUtils {

    static public boolean isValidSubtree(long start, long end) {
        // TODO add exceptions ?
        long size = end - start;
        long bitCeil = bitCeil(size);
        return start % bitCeil == 0;
    }

    //Smallest power of 2 greater or equal than n
    static public long bitCeil(long n){
        if(n <= 1){
            return 1;
        }
        return Long.highestOneBit(n) << (Long.bitCount(n) > 1 ? 1 : 0);
    }

    // If is not full is partial
    static public boolean isFullSubtree(long start, long end) {

        return Long.bitCount(end - start) == 1;
    }

    static public int largestPowerOfTwoSmallerThan(int n) {
        int highestOneBit = Integer.highestOneBit(n);
        if (highestOneBit == n) {
            return n / 2;
        }
        return highestOneBit;
    }

    static public boolean isPowerOfTwo(long n) {
        return n > 0 && (n == Long.highestOneBit(n));
    }

}
