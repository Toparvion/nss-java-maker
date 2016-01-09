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
