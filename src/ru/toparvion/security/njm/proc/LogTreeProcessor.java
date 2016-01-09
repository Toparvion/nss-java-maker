/*
 *     NSS Java Maker - your magic wand for SSL/TLS traffic decryption.
 *     Copyright © 2015 Toparvion <toparvion at gmx dot com>
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package ru.toparvion.security.njm.proc;

import ru.toparvion.security.njm.LogTree;
import ru.toparvion.security.njm.Node;
import ru.toparvion.security.njm.NssFileEntry;
import ru.toparvion.security.njm.TokenNotFoundException;

/**
 * Public contract for classes capable of handling a log tree for extracting the NSS file pieces.
 */
public interface LogTreeProcessor {
  /**
   * Queries the <code>logTree</code> for corresponding NSS file pieces and returns composed entry.
   * @param branchOrigin node from which the search is to be started
   * @param logTree log tree to query
   * @return out file entry
   */
  NssFileEntry process(Node branchOrigin, LogTree logTree) throws TokenNotFoundException;
}
