package ru.toparvion.security.njm.proc;

import ru.toparvion.security.njm.LogTree;
import ru.toparvion.security.njm.Node;
import ru.toparvion.security.njm.NssFileEntry;
import ru.toparvion.security.njm.TokenNotFoundException;

/**
 * Log tree processor for extracting NSS file pieces required in Diffie-Hellman encryption mode.
 */
public class DhLogTreeProcessor implements LogTreeProcessor {

  private static final String MODE = "CLIENT_RANDOM";

  @Override
  public NssFileEntry process(Node branchOrigin, LogTree logTree) throws TokenNotFoundException {

    String clientRandom = logTree
            .get(branchOrigin, "ClientHello", "[write] MD5 and SHA1 hashes", "0000", "0010", "0020")
            .orElseThrow(() -> new TokenNotFoundException("No ClientRandom value found in the log."))
            .substring(12, 76);

    String masterSecret = logTree
            .get(branchOrigin, "ClientKeyExchange", "Master Secret", "0000", "0010", "0020")
            .orElseThrow(() -> new TokenNotFoundException("No Master Secret found in the log."));

    return new NssFileEntry(MODE, clientRandom, masterSecret);

  }
}
