package de.mtg.jplants.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TreeUtilsTest {
    @Test
    void isValidSubtreeTest(){
        boolean result1 = TreeUtils.isValidSubtree(4, 8);
        assertTrue(result1);
        boolean result2 = TreeUtils.isValidSubtree(8,13);
        assertTrue(result2);
        boolean falseResult = TreeUtils.isValidSubtree(1,13);
        assertFalse(falseResult);
    }
}
