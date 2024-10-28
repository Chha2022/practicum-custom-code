import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.util.Date;

public class GenerateCertificate {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(4096, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Generate certificate
        X500Name dnName = new X500Name("CN=localhost");
        BigInteger certSerialNumber = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + 365L * 24L * 60L * 60L * 1000L); // 1 year validity
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));

        // Save the certificate and private key
        try (FileOutputStream certOut = new FileOutputStream("cert.pem")) {
            certOut.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            certOut.write(java.util.Base64.getEncoder().encode(certificate.getEncoded()));
            certOut.write("\n-----END CERTIFICATE-----\n".getBytes());
        }

        try (FileOutputStream keyOut = new FileOutputStream("key.pem")) {
            keyOut.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
            keyOut.write(java.util.Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()));
            keyOut.write("\n-----END PRIVATE KEY-----\n".getBytes());
        }

        System.out.println("Certificate and key generated successfully.");
    }
}
