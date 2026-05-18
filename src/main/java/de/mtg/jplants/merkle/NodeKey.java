package de.mtg.jplants.merkle;

/**
 * The interval is always [p * 2^l, (p+1) * 2^l)
 * @param level the subtree covers 2^l leaves
 * @param position the subtree starts at leaf index p * 2^l
 */
public record NodeKey(long level, long position){

}