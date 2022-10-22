from unittest.case import TestCase
from ellipticcurve import Ecdsa, PrivateKey, PublicKey, Signature, File


class OpensslTest(TestCase):

    def testRecoverInternal(self):
        for _ in range(1000):
            privateKey = PrivateKey()
            publicKey = privateKey.publicKey()
            publicKeyString = publicKey.toCompressed()

            recoverCompressed = PublicKey.fromCompressed(publicKeyString, publicKey.curve)

            self.assertTrue(publicKey.curve.G == recoverCompressed.curve.G)

    def recoverFromStringEven(self):
        publicKeyString = "52972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab288742f4dc97d9edb6fd946babc002fdfb06f26caf117b9405ed79275763fdb1c"
        compPubKeyString = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"

        publicKey = PublicKey.fromCompressed(compPubKeyString)

        self.assertTrue(publicKeyString == publicKey.toString())

    def recoverFromStringOdd(self):
        publicKeyString = "18ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f504c220d01e1ca419cb1ba4b3393b615e99dd20aa6bf071078f70fd949008e7411"
        compPubKeyString = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"

        publicKey = PublicKey.fromCompressed(compPubKeyString)

        self.assertTrue(publicKeyString == publicKey.toString())

    def compareToCompressedEven(self):
        privateKey = PrivateKey.fromString("f91d8f3a49805fff9289769247e984b355939679f3080156fe295229e00f25af")
        publicKey = privateKey.publicKey()

        compPublicKey = publicKey.toCompressed()
        controlPublicKey = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"

        self.assertTrue(compPublicKey == controlPublicKey)

    def compareToCompressedOdd(self):
        privateKey = PrivateKey.fromString("ac609e0cc9681f8cb63e968be20e0f19721751561944f5b4e52d54d5f27ec57b")
        publicKey = privateKey.publicKey()

        compPublicKey = publicKey.toCompressed()
        controlPublicKey = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"

        self.assertTrue(compPublicKey == controlPublicKey)
