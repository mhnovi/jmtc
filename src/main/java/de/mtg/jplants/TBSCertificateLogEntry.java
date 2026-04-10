package de.mtg.jplants;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.Time;

/**
 * <pre>
 * TBSCertificateLogEntry ::= SEQUENCE {
 * version               [0] EXPLICIT Version DEFAULT v1,
 * issuer                    Name,
 * validity                  Validity,
 * subject                   Name,
 * subjectPublicKeyAlgorithm AlgorithmIdentifier{PUBLIC-KEY,
 * {PublicKeyAlgorithms}},
 * subjectPublicKeyInfoHash  OCTET STRING,
 * issuerUniqueID        [1] IMPLICIT UniqueIdentifier OPTIONAL,
 * subjectUniqueID       [2] IMPLICIT UniqueIdentifier OPTIONAL,
 * extensions            [3] EXPLICIT Extensions{{CertExtensions}}
 * OPTIONAL
 * }
 * </pre>
 */
public class TBSCertificateLogEntry extends ASN1Object {

    private ASN1Integer version;
    private X500Name issuer;
    private Time startDate;
    private Time endDate;
    private X500Name subject;
    private AlgorithmIdentifier subjectPublicKeyInfoAlgorithm;
    private ASN1OctetString subjectPublicKeyInfoHash;
    private ASN1BitString issuerUniqueID;
    private ASN1BitString subjectUniqueID;
    private Extensions extensions;

    public static TBSCertificateLogEntry getInstance(Object obj) {
        if (obj instanceof TBSCertificateLogEntry) {
            return (TBSCertificateLogEntry) obj;
        } else if (obj != null) {
            return new TBSCertificateLogEntry(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public TBSCertificateLogEntry() {
        // empty
    }

    private TBSCertificateLogEntry(ASN1Sequence sequence) {

        int index = 0;

        ASN1Encodable entry = sequence.getObjectAt(0);
        if (entry instanceof ASN1TaggedObject) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) entry;
            if (tagged.getTagNo() != 0) {
                throw new IllegalArgumentException(String.format("Wrong tag %d for version.", tagged.getTagNo()));
            }
            version = ASN1Integer.getInstance(tagged, true);
            ++index;
        }

        issuer = X500Name.getInstance(sequence.getObjectAt(index++));

        ASN1Sequence validity = ASN1Sequence.getInstance(sequence.getObjectAt(index++));
        startDate = Time.getInstance(validity.getObjectAt(0));
        endDate = Time.getInstance(validity.getObjectAt(1));

        subject = X500Name.getInstance(sequence.getObjectAt(index++));

        subjectPublicKeyInfoAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(index++));
        subjectPublicKeyInfoHash = ASN1OctetString.getInstance(sequence.getObjectAt(index++));

        if (index < sequence.size()) {
            ASN1TaggedObject extra = (ASN1TaggedObject) sequence.getObjectAt(index);

            if (extra.getTagNo() == 1) {
                issuerUniqueID = DERBitString.getInstance(extra, false);
                ++index;
            }
        }

        if (index < sequence.size()) {
            ASN1TaggedObject extra = (ASN1TaggedObject) sequence.getObjectAt(index);

            if (extra.getTagNo() == 2) {
                subjectUniqueID = DERBitString.getInstance(extra, false);
                ++index;
            }
        }

        if (index < sequence.size()) {
            ASN1TaggedObject extra = (ASN1TaggedObject) sequence.getObjectAt(index);

            if (extra.getTagNo() == 3) {
                extensions = Extensions.getInstance(ASN1Sequence.getInstance(extra, true));
                ++index;
            }
        }

        if (index < sequence.size()) {
            throw new IllegalArgumentException("Wrong sequence size");
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        if (version != null && version.getValue().compareTo(BigInteger.ZERO) != 0) {
            vector.add(new DERTaggedObject(true, 0, version));
        }

        vector.add(issuer);

        ASN1EncodableVector validity = new ASN1EncodableVector();
        validity.add(startDate);
        validity.add(endDate);
        vector.add(new DERSequence(validity));

        vector.add(subject);

        vector.add(subjectPublicKeyInfoAlgorithm);
        vector.add(subjectPublicKeyInfoHash);

        if (issuerUniqueID != null) {
            vector.add(new DERTaggedObject(false, 1, issuerUniqueID));
        }

        if (subjectUniqueID != null) {
            vector.add(new DERTaggedObject(false, 2, subjectUniqueID));
        }

        if (extensions != null) {
            vector.add(new DERTaggedObject(true, 3, this.extensions));
        }

        return new DERSequence(vector);
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public void setVersion(ASN1Integer version) {
        this.version = version;
    }

    public int getVersionNumber() {
        return (version == null) ? 1 : (version.getValue().intValue() + 1);
    }

    public void setVersionNumber(int vNum) {
        version = (vNum == 1) ? null : new ASN1Integer(vNum - 1);
    }

    public X500Name getIssuer() {
        return issuer;
    }

    public void setIssuer(X500Name issuer) {
        this.issuer = issuer;
    }

    public Time getStartDate() {
        return startDate;
    }

    public void setStartDate(Time startDate) {
        this.startDate = startDate;
    }

    public Time getEndDate() {
        return endDate;
    }

    public void setEndDate(Time endDate) {
        this.endDate = endDate;
    }


    public X500Name getSubject() {
        return subject;
    }

    public void setSubject(X500Name subject) {
        this.subject = subject;
    }

    public AlgorithmIdentifier getSubjectPublicKeyInfoAlgorithm() {
        return subjectPublicKeyInfoAlgorithm;
    }

    public void setSubjectPublicKeyInfoAlgorithm(AlgorithmIdentifier subjectPublicKeyInfoAlgorithm) {
        this.subjectPublicKeyInfoAlgorithm = subjectPublicKeyInfoAlgorithm;
    }

    public void setSubjectPublicKeyInfoHash(ASN1OctetString subjectPublicKeyInfoHash) {
        this.subjectPublicKeyInfoHash = subjectPublicKeyInfoHash;
    }

    public ASN1BitString getIssuerUniqueID() {
        return issuerUniqueID;
    }

    public void setIssuerUniqueID(ASN1BitString issuerUniqueID) {
        this.issuerUniqueID = issuerUniqueID;
    }

    public ASN1BitString getSubjectUniqueID() {
        return subjectUniqueID;
    }

    public void setSubjectUniqueID(ASN1BitString subjectUniqueID) {
        this.subjectUniqueID = subjectUniqueID;
    }

    public ASN1OctetString getSubjectPublicKeyInfoHash() {
        return subjectPublicKeyInfoHash;
    }

    public Extensions getExtensions() {
        return extensions;
    }

    public void setExtensions(Extensions extensions) {
        this.extensions = extensions;
    }

}
