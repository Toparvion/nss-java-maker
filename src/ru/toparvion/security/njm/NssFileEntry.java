package ru.toparvion.security.njm;

/**
 * A POJO representing one line of NSS file.
 */
public class NssFileEntry {
  String mode;
  String firstToken;
  String secondToken;

  public NssFileEntry(String mode, String firstToken, String secondToken) {
    this.mode = mode;
    this.firstToken = firstToken;
    this.secondToken = secondToken;
  }

  @Override
  public String toString() {
    return String.format("%s %s %s", mode, firstToken, secondToken);
  }
}
