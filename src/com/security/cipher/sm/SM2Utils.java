package com.security.cipher.sm;

import org.bouncycastle.asn1.*;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

public class SM2Utils {
    private static final int c1XYL = 64;
    private static final int c3L = 64;

    public static String dlscEncrypt(String publicKeyStr, String endata) throws IOException {
        if (publicKeyStr == null || publicKeyStr.length() == 0 ||
                endata == null || endata.length() == 0) {
            return null;
        }
        byte[] publicKey = Util.hexToByte(publicKeyStr);
//        byte[] data = endata.getBytes();
        // 密文16进制时
        byte[] data = Util.hexToByte(endata);
        StringBuffer sb = new StringBuffer(490);
        byte[] source = new byte[data.length];
        System.arraycopy(data, 0, source, 0, data.length);

        Cipher cipher = new Cipher();
        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

        ECPoint c1 = cipher.Init_enc(sm2, userKey);
        cipher.Encrypt(source);
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);

        String x = c1.getX().toBigInteger().toString(16).toUpperCase();
        String y = c1.getY().toBigInteger().toString(16).toUpperCase();
        while (x.length() < 64) {
            x = "0" + x;
        }
        while (y.length() < 64) {
            y = "0" + y;
        }
        sb.append(x);
        sb.append(y);
        sb.append(Util.byteToHex(source));
        sb.append(Util.byteToHex(c3));
        return sb.toString();
    }

    public static String dlscDecrypt(String prik, String encryStr) throws IOException {
        if (prik == null || prik.length() == 0 ||
                encryStr == null || encryStr.length() == 0) {
            return null;
        }
        byte[] privateKey = Util.hexToByte(prik);
        byte[] encryptedData = Util.hexToByte(encryStr);
        String data = Util.byteToHex(encryptedData);
        byte[] c1Bytesx = Util.hexToByte(data.substring(0, c1XYL));
        byte[] c1Bytesy = Util.hexToByte(data.substring(c1XYL, c1XYL << 1));
        byte[] c2 = Util.hexToByte(data.substring(c1XYL << 1, data.length() - c1XYL));
        byte[] c3 = Util.hexToByte(data.substring(data.length() - c3L));
        SM2 sm2 = SM2.Instance();
        BigInteger userD = new BigInteger(1, privateKey);
        ECPoint c1 = new ECPoint.Fp(new ECCurve.Fp(sm2.ecc_p, sm2.ecc_a, sm2.ecc_b),
                new Fp(sm2.ecc_p, Util.byteConvertInteger(c1Bytesx)),
                new Fp(sm2.ecc_p, Util.byteConvertInteger(c1Bytesy)));
        Cipher cipher = new Cipher();
        cipher.Init_dec(userD, c1);
        cipher.Decrypt(c2);
        cipher.Dofinal(c3);
//        return new String(c2);
        // 密文16进制时
        return Util.getHexString(c2);
    }

    public static byte[] encrypt(byte[] publicKey, byte[] data) throws IOException {
        if (publicKey == null || publicKey.length == 0) {
            return null;
        }

        if (data == null || data.length == 0) {
            return null;
        }

        byte[] source = new byte[data.length];
        System.arraycopy(data, 0, source, 0, data.length);

        Cipher cipher = new Cipher();
        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

        ECPoint c1 = cipher.Init_enc(sm2, userKey);
        cipher.Encrypt(source);
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);

        DERInteger x = new DERInteger(c1.getX().toBigInteger());
        DERInteger y = new DERInteger(c1.getY().toBigInteger());
        DEROctetString derDig = new DEROctetString(c3);
        DEROctetString derEnc = new DEROctetString(source);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(x);
        v.add(y);
        v.add(derDig);
        v.add(derEnc);
        DERSequence seq = new DERSequence(v);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DEROutputStream dos = new DEROutputStream(bos);
        dos.writeObject(seq);
        return bos.toByteArray();
    }

    public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
        if (privateKey == null || privateKey.length == 0) {
            return null;
        }

        if (encryptedData == null || encryptedData.length == 0) {
            return null;
        }

        byte[] enc = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0, enc, 0, encryptedData.length);

        SM2 sm2 = SM2.Instance();
        BigInteger userD = new BigInteger(1, privateKey);

        ByteArrayInputStream bis = new ByteArrayInputStream(enc);
        ASN1InputStream dis = new ASN1InputStream(bis);
        DERObject derObj = dis.readObject();
        ASN1Sequence asn1 = (ASN1Sequence) derObj;
        DERInteger x = (DERInteger) asn1.getObjectAt(0);
        DERInteger y = (DERInteger) asn1.getObjectAt(1);
        ECPoint c1 = sm2.ecc_curve.createPoint(x.getValue(), y.getValue(), true);

        Cipher cipher = new Cipher();
        cipher.Init_dec(userD, c1);
        DEROctetString data = (DEROctetString) asn1.getObjectAt(3);
        enc = data.getOctets();
        cipher.Decrypt(enc);
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);
        return enc;
    }

    public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData) throws IOException {
        if (privateKey == null || privateKey.length == 0) {
            return null;
        }

        if (sourceData == null || sourceData.length == 0) {
            return null;
        }

        SM2 sm2 = SM2.Instance();
        BigInteger userD = new BigInteger(privateKey);
        System.out.println("userD: " + userD.toString(16));
        System.out.println("");

        ECPoint userKey = sm2.ecc_point_g.multiply(userD);
        System.out.println("椭圆曲线点X: " + userKey.getX().toBigInteger().toString(16));
        System.out.println("椭圆曲线点Y: " + userKey.getY().toBigInteger().toString(16));
        System.out.println("");

        SM3Digest sm3 = new SM3Digest();
        byte[] z = sm2.sm2GetZ(userId, userKey);
        System.out.println("SM3摘要Z: " + Util.getHexString(z));
        System.out.println("");

        System.out.println("M: " + Util.getHexString(sourceData));
        System.out.println("");

        sm3.update(z, 0, z.length);
        sm3.update(sourceData, 0, sourceData.length);
        byte[] md = new byte[32];
        sm3.doFinal(md, 0);

        System.out.println("SM3摘要值: " + Util.getHexString(md));
        System.out.println("");

        SM2Result sm2Result = new SM2Result();
        sm2.sm2Sign(md, userD, userKey, sm2Result);
        System.out.println("r: " + sm2Result.r.toString(16));
        System.out.println("s: " + sm2Result.s.toString(16));
        System.out.println("");

        DERInteger d_r = new DERInteger(sm2Result.r);
        DERInteger d_s = new DERInteger(sm2Result.s);
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(d_r);
        v2.add(d_s);
        DERObject sign = new DERSequence(v2);
        byte[] signdata = sign.getDEREncoded();
        return signdata;
    }

    public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData) throws IOException {
        if (publicKey == null || publicKey.length == 0) {
            return false;
        }

        if (sourceData == null || sourceData.length == 0) {
            return false;
        }

        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

        SM3Digest sm3 = new SM3Digest();
        byte[] z = sm2.sm2GetZ(userId, userKey);
        sm3.update(z, 0, z.length);
        sm3.update(sourceData, 0, sourceData.length);
        byte[] md = new byte[32];
        sm3.doFinal(md, 0);
        System.out.println("SM3摘要值: " + Util.getHexString(md));
        System.out.println("");

        ByteArrayInputStream bis = new ByteArrayInputStream(signData);
        ASN1InputStream dis = new ASN1InputStream(bis);
        DERObject derObj = dis.readObject();
        Enumeration<DERInteger> e = ((ASN1Sequence) derObj).getObjects();
        BigInteger r = e.nextElement().getValue();
        BigInteger s = e.nextElement().getValue();
        SM2Result sm2Result = new SM2Result();
        sm2Result.r = r;
        sm2Result.s = s;
        System.out.println("r: " + sm2Result.r.toString(16));
        System.out.println("s: " + sm2Result.s.toString(16));
        System.out.println("");


        sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
        return sm2Result.r.equals(sm2Result.R);
    }


    public static void main(String[] args) throws Exception {
        // DLSC
        String dlscText = "EA4EC352F076A6BE";
        String prik = "E7CB09606A53320B347F61F3F142DCB118F723A9BC27879F2805BE778F24AEE5";
        String pubk = "04C4F7D581BEFEF25C8BBB6DAD52A6AB8234FA7DB7A988592BC592DAF2BE630647E3746788CBDC59042D85260DD48B6A7347D82C5314E8AC261588A33151DFCA17";
        //第一组
        //String pubk = "04F6D326509BA8DA09AA34CD85AEF79DBA45FD17E675541B15EF5EC9B8F4AB18BCA13A2F04C6BC1607CA72CC296A9ACF7BF26891C32B210B947CA88F3B92801E8F";
        //第二组
        //String pubk = "04C4F7D581BEFEF25C8BBB6DAD52A6AB8234FA7DB7A988592BC592DAF2BE630647E3746788CBDC59042D85260DD48B6A7347D82C5314E8AC261588A33151DFCA17";
        //第三组
        //String pubk = "04A2C0BFFCC4B36A6064F88600C7171A67B293A03E9BBFA3C28EA2DD496D1A6EC701D29EA7C8D2AB9DC85CAA7F9E24A730CAEA8FF3670FAFD6B28D10F9531ECF50";

//        String plainText = "message digest";
//        byte[] sourceData = plainText.getBytes();
//        // 国密规范测试
//        String userId = "ALICE123@YAHOO.COM";
//        System.out.println("ID: " + Util.getHexString(userId.getBytes()));
//        System.out.println("");
//        // 国密规范测试
//        String prik = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
//        String pubk = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857"
//        String prikS = new String(Base64.encode(Util.hexToByte(prik)));
//        String pubkS = new String(Base64.encode(Util.hexToByte(pubk)));
//        System.out.println("prikS: " + prikS);
//        System.out.println("");
//        System.out.println("pubkS: " + pubkS);
//        System.out.println("");
//        System.out.println("签名: ");
//        byte[] c = SM2Utils.sign(userId.getBytes(), Base64.decode(prikS.getBytes()), sourceData);
//        System.out.println("sign: " + Util.getHexString(c));
//        System.out.println("");
//        System.out.println("验签: ");
//        boolean vs = SM2Utils.verifySign(userId.getBytes(), Base64.decode(pubkS.getBytes()), sourceData, c);
//        System.out.println("验签结果: " + vs);
//        System.out.println("");
//        System.out.println("加密: ");
//        byte[] cipherText = SM2Utils.encrypt(Base64.decode(pubkS.getBytes()), sourceData);
//        System.out.println(new String(Base64.encode(cipherText)));
//        System.out.println("");
//        System.out.println("解密: ");
//        plainText = new String(SM2Utils.decrypt(Base64.decode(prikS.getBytes()), cipherText));
//        System.out.println(plainText);


        System.out.println("加密: ");
        String cipherText = SM2Utils.dlscEncrypt(pubk, dlscText);
        System.out.println(cipherText);
        System.out.println("解密: ");
        dlscText = SM2Utils.dlscDecrypt(prik, cipherText);
        System.out.println(dlscText);



    }
}
