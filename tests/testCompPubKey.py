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
