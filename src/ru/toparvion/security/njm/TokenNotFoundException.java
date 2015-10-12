package ru.toparvion.security.njm;

/**
 * Special exception with additional info message.
 */
public class TokenNotFoundException extends Exception {
  private static final String AUX_INFO = " Please make sure your log was written with " +
          "'-Djavax.net.debug=ssl:handshake:data' JVM option enabled.";

  public TokenNotFoundException(String message) {
    super(message + AUX_INFO);
  }
}
