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

import java.util.ArrayList;
import java.util.List;

/**
 * Single node of log tree. Consists of a token name (defining the node itself) and a collection of child nodes.
 */
public class Node {
  private String token;
  private List<Node> children;

  public Node(String token, List<Node> children) {
    this.token = token;
    this.children = children;
  }

  public Node(String token) {
    this.token = token;
    this.children = new ArrayList<>();
  }

  public String getToken() {
    return token;
  }

  public List<Node> getChildren() {
    return children;
  }

  @Override
  public String toString() {
    return "Node{" +
            "token='" + token + '\'' +
            ", childrenSize=" + children.size() +
            '}';
  }
}
