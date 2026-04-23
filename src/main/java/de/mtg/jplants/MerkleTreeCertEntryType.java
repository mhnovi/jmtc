package de.mtg.jplants;

public enum MerkleTreeCertEntryType {
    NULL_ENTRY(0),
    TBS_CERT_ENTRY(1);

    private final int value;

    MerkleTreeCertEntryType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static MerkleTreeCertEntryType fromValue(int value) {
        for (MerkleTreeCertEntryType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown MerkleTreeCertEntryType value: " + value);
    }
}
