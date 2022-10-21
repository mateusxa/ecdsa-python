from operator import inv
from .math import Math
from .point import Point
from .curve import secp256k1, getByOid
from .utils.pem import getPemContent, createPem
from .utils.der import hexFromInt, parse, DerFieldType, encodeConstructed, encodePrimitive
from .utils.binary import hexFromByteString, byteStringFromHex, intFromHex, base64FromByteString, byteStringFromBase64


class PublicKey:

    def __init__(self, point, curve):
        self.point = point
        self.curve = curve

    def toString(self, encoded=False, compressed=False):
        baseLength = 2 * self.curve.length()
        xHex = hexFromInt(self.point.x).zfill(baseLength)
        yHex = hexFromInt(self.point.y).zfill(baseLength)
        string = xHex + yHex
        if encoded:
            return "0004" + string
        return string

    def toCompressed(self):
        baseLength = 2 * self.curve.length()
        prefix = "02" if self.point.y % 2 == 0 else "03"
        xHex = hexFromInt(self.point.x).zfill(baseLength)
        return prefix + xHex

    def toDer(self):
        hexadecimal = encodeConstructed(
            encodeConstructed(
                encodePrimitive(DerFieldType.object, _ecdsaPublicKeyOid),
                encodePrimitive(DerFieldType.object, self.curve.oid),
            ),
            encodePrimitive(DerFieldType.bitString, self.toString(encoded=True)),
        )
        return byteStringFromHex(hexadecimal)

    def toPem(self):
        der = self.toDer()
        return createPem(content=base64FromByteString(der), template=_pemTemplate)

    @classmethod
    def fromPem(cls, string):
        publicKeyPem = getPemContent(pem=string, template=_pemTemplate)
        return cls.fromDer(byteStringFromBase64(publicKeyPem))

    @classmethod
    def fromDer(cls, string):
        hexadecimal = hexFromByteString(string)
        curveData, pointString = parse(hexadecimal)[0]
        publicKeyOid, curveOid = curveData
        if publicKeyOid != _ecdsaPublicKeyOid:
            raise Exception("The Public Key Object Identifier (OID) should be {ecdsaPublicKeyOid}, but {actualOid} was found instead".format(
                ecdsaPublicKeyOid=_ecdsaPublicKeyOid,
                actualOid=publicKeyOid,
            ))
        curve = getByOid(curveOid)
        return cls.fromString(string=pointString, curve=curve)

    @classmethod
    def fromString(cls, string, curve=secp256k1, validatePoint=True):
        baseLength = 2 * curve.length()
        if len(string) > 2 * baseLength and string[:4] == "0004":
            string = string[4:]

        xs = string[:baseLength]
        ys = string[baseLength:]

        p = Point(
            x=intFromHex(xs),
            y=intFromHex(ys),
        )
        publicKey = PublicKey(point=p, curve=curve)
        if not validatePoint:
            return publicKey
        if p.isAtInfinity():
            raise Exception("Public Key point is at infinity")
        if not curve.contains(p):
            raise Exception("Point ({x},{y}) is not valid for curve {name}".format(x=p.x, y=p.y, name=curve.name))
        if not Math.multiply(p=p, n=curve.N, N=curve.N, A=curve.A, P=curve.P).isAtInfinity():
            raise Exception("Point ({x},{y}) * {name}.N is not at infinity".format(x=p.x, y=p.y, name=curve.name))
        return publicKey
        
    @classmethod
    def fromCompressed(cls, string, curve=secp256k1):
        prefix, xString  = string[:2], string[2:]
        if prefix not in ["02", "03"]:
            raise Exception("Compressed string should start with 02 or 03")

        is_even = prefix == "02"
        x = intFromHex(xString)

        alpha = (pow(x, 3, curve.P) + curve.A * x + curve.B) % curve.P
        try:
            beta = pow(alpha, (curve.P + 1) // 4, curve.P)
        except ValueError:
            raise Exception("Point ({x},{y}) is not valid for curve {name}".format(x=x, y=beta, name=curve.name))

        if is_even == bool(beta & 1):
            y = curve.P - beta
        else:
            y = beta

        return cls(Point(x, y), curve)


_ecdsaPublicKeyOid = (1, 2, 840, 10045, 2, 1)


_pemTemplate = """
-----BEGIN PUBLIC KEY-----
{content}
-----END PUBLIC KEY-----
"""
