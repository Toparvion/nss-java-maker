package ru.toparvion.security.njm.proc;

import ru.toparvion.security.njm.LogTree;
import ru.toparvion.security.njm.NssFileEntry;

/**
 * Public contract for classes capable of handling a log tree for extracting the NSS file pieces.
 */
public interface LogTreeProcessor {
  /**
   * Queries the <code>logTree</code> for corresponding NSS file pieces and returns composed entry.
   * @param logTree log tree to query
   * @return out file entry
   */
  NssFileEntry process(LogTree logTree);
}
