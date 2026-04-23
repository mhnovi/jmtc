package de.mtg.jplants;

import java.util.Arrays;
import java.util.Objects;

public class MerkleTreeCertEntry {

    private MerkleTreeCertEntryType type;
    private final byte[] tbsCertEntryData;

    private MerkleTreeCertEntry() {
        this.type = MerkleTreeCertEntryType.NULL_ENTRY;
        this.tbsCertEntryData = null;
    }

    private MerkleTreeCertEntry(byte[] tbsCertEntryData) {
        Objects.requireNonNull(tbsCertEntryData, "tbsCertEntryData must not be null");
        this.type = MerkleTreeCertEntryType.TBS_CERT_ENTRY;
        this.tbsCertEntryData = Arrays.copyOf(tbsCertEntryData, tbsCertEntryData.length);
    }
}
