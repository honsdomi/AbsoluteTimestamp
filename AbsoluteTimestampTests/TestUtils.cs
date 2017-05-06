using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;

namespace TimestampLibraryTests
{
    class TestUtils
    {
        public static ISignatureFactory GetSignatureFactory()
        {
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);
            AsymmetricCipherKeyPair subjectKeyPair = default(AsymmetricCipherKeyPair);
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, 4096);

            IAsymmetricCipherKeyPairGenerator keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;

            return new Asn1SignatureFactory("MD5WithRSA", issuerKeyPair.Private, random);
        }


        public static X509Certificate GenerateCertificate(ISignatureFactory signatureFactory)
        {
            RsaKeyPairGenerator keypairgen = new RsaKeyPairGenerator();
            keypairgen.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 1024));

            AsymmetricCipherKeyPair keypair = keypairgen.GenerateKeyPair();

            BigInteger SN = BigInteger.ProbablePrime(120, new Random());
            X509Name CN = new X509Name("CN=Test CN");
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetSerialNumber(SN);
            certificateGenerator.SetSubjectDN(CN);
            certificateGenerator.SetIssuerDN(CN);
            certificateGenerator.SetNotAfter(DateTime.Now.AddDays(10));
            certificateGenerator.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            certificateGenerator.SetPublicKey(keypair.Public);

            return certificateGenerator.Generate(signatureFactory);
        }

        public static X509Crl GenerateCrl(X509Certificate certificate, ISignatureFactory signatureFactory, int reason)
        {
            X509V2CrlGenerator crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(new X509Name("CN=Test CA"));

            DateTime now = DateTime.Now;
            crlGen.SetThisUpdate(now);
            crlGen.SetNextUpdate(DateTime.Now.AddDays(10));

            crlGen.AddCrlEntry(certificate.SerialNumber, now, reason);

            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(certificate));
            crlGen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));

            return crlGen.Generate(signatureFactory);
        }

        /// <summary>
        /// Shorter implementation of TimestampVerifier.IsValidAfterRevocation method for testing purposes.
        /// </summary>
        public static bool IsValidAfterRevocationFake(X509Crl crl, X509Certificate cert, DateTime timestampGenTime)
        {
            if (crl.IsRevoked(cert))
            {
                X509CrlEntry revokedEntry = crl.GetRevokedCertificate(cert.SerialNumber);
                DateTime revocationDate = revokedEntry.RevocationDate;

                /* All timestamps created after revocation date are invalid */
                if (DateTime.Compare(timestampGenTime, revocationDate) > 0)
                {
                    return false;
                }

                DerEnumerated reasonCode = DerEnumerated.GetInstance(GetExtensionValue(revokedEntry, X509Extensions.ReasonCode));

                /* If the revocation reason is not present, the timestamp is considered invalid */
                if (reasonCode == null)
                {
                    return false;
                }

                int reason = reasonCode.Value.IntValue;

                /* If the revocation reason is any other value, the timestamp is considered invalid */
                if (!(reason == CrlReason.Unspecified ||
                    reason == CrlReason.AffiliationChanged ||
                    reason == CrlReason.Superseded ||
                    reason == CrlReason.CessationOfOperation))
                {
                    return false;
                }
            }
            return true;
        }

        private static Asn1Object GetExtensionValue(IX509Extension ext, DerObjectIdentifier oid)
        {
            Asn1OctetString bytes = ext.GetExtensionValue(oid);

            if (bytes == null)
                return null;

            return Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(bytes);
        }
    }
}
