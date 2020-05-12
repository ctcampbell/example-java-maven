package com.srcclr;

import org.apache.commons.fileupload.MultipartStream;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.web.util.UriUtils;

import java.io.ByteArrayInputStream;

public class Main {

  public static void main(String[] args) throws Exception {
    String candidate = args[0];
    // Vulnerable method call 1
    String hashed = BCrypt.hashpw(candidate, BCrypt.gensalt(12));

    // Vulnerable method call 2
    BCrypt.checkpw(candidate, hashed);

    filterXMLSignature();

    // Update Advisor: changed in the upgrade from Spring Web 3.1.1.RELEASE to 3.2.15.RELEASE
    UriUtils.encodeFragment("", "");
  }

  private static void filterXMLSignature() {
    byte[] bytes = new byte[256];

    new MultipartStream(new ByteArrayInputStream(bytes), bytes);

    new XMLSignatureInput(bytes).addNodeFilter(null);
  }
}
