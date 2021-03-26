package com.red.kites.autoconfigure.saml.authentication;

import org.apache.tomcat.util.buf.HexUtils;
import sun.misc.BASE64Encoder;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class SSOUtils {
    public static String getName(String name) {
        name = name.replaceAll("^(0+)", "");
        return new BASE64Encoder().encode(name.getBytes());
    }

    public static String getTime(Date time) throws ParseException {
        if (time == null) {
            time = new Date();
        }
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss", Locale.CHINA);
        return format.format(time);
    }

    public static String getEncrypt(String parameter) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] data = parameter.getBytes(StandardCharsets.UTF_8);
        md.update(data);
        byte[] digestedByteArray = md.digest();
        return HexUtils.toHexString(digestedByteArray);
    }
}