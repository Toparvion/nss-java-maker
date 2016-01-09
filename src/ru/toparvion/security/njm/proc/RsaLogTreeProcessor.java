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
 * Log tree processor for extracting NSS file pieces required in RSA encryption mode.
 */
public class RsaLogTreeProcessor implements LogTreeProcessor {

  private static final String MODE = "RSA";

  @Override
  public NssFileEntry process(Node branchOrigin, LogTree logTree) throws TokenNotFoundException {

    String encPreMaster = logTree
            .get(branchOrigin, "ClientKeyExchange", "[write] MD5 and SHA1 hashes", "0000")
            .orElseThrow(() -> new TokenNotFoundException("No encrypted PreMaster Secret found in the log."))
            .substring(12, 28);

    String decPreMaster = logTree
            .get(branchOrigin, "ClientKeyExchange", "PreMaster Secret", "0000", "0010", "0020")
            .orElseThrow(() -> new TokenNotFoundException("No PreMaster Secret found in the log."));

    return new NssFileEntry(MODE, encPreMaster, decPreMaster);

  }
}
