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
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * A fixed depth tree for effective searching through SSL/TLS log content.
 */
public class LogTree {
  private static final Pattern RAW_DATA_LINE_REGEXP = Pattern.compile("^\\w{4}: ");

  LinkedList<Node> nodesLevel_0 = new LinkedList<>();
  static final Predicate<String> PREDICATE_LEVEL_0 = s -> s.startsWith("*** ClientHello");

  LinkedList<Node> nodesLevel_1 = new LinkedList<>();
  static final Predicate<String> PREDICATE_LEVEL_1 = s -> s.startsWith("*** ");

  LinkedList<Node> nodesLevel_2 = new LinkedList<>();
  static final Predicate<String> PREDICATE_LEVEL_2 = RAW_DATA_LINE_REGEXP.asPredicate().negate();

  LinkedList<Node> nodesLevel_3 = new LinkedList<>();
  static final Predicate<String> PREDICATE_LEVEL_3 = RAW_DATA_LINE_REGEXP.asPredicate();

  Node root = new Node("root", new ArrayList<>(nodesLevel_0));

  /**
   * Traverses the tree through specified levels' tokens and returns third level nodes' content (HEX dump), if found.
   *
   * @param branchOrigin a Node that represents the origin of log conversation branch
   * @param level_1 first level token; must not be <code>null</code>
   * @param level_2 second level token; may be <code>null</code>
   * @param level_3 third level tokens (several tokens mean returning the concatenation of all matched nodes); may be
   *                <code>null</code>
   * @return found nodes content, if any
   */
  public Optional<String> get(Node branchOrigin, String level_1, String level_2, String... level_3) {
    Optional<Node> nodeLevel_1 = branchOrigin.getChildren()
            .stream()
            .filter(node -> node.getToken().contains(level_1))
            .findFirst();
    if (!nodeLevel_1.isPresent()) {
      return Optional.empty();
    }
    if (level_2 == null) {
      return Optional.ofNullable(nodeLevel_1.get().getToken());
    }

    Optional<Node> nodeLevel_2 = nodeLevel_1.get()
            .getChildren()
            .stream()
            .filter(node -> node.getToken().startsWith(level_2))
            .findFirst();
    if (!nodeLevel_2.isPresent()) {
      return Optional.empty();
    }
    if (level_3 == null) {
      return Optional.ofNullable(nodeLevel_2.get().getToken());
    }

    List<Node> childrenLevel_3 = nodeLevel_2.get().getChildren();
    return childrenLevel_3.stream()
            .filter(node -> Stream.of(level_3)
                            .anyMatch(s -> node.getToken().startsWith(s))
            )
            .map(Node::getToken)
            .map(s -> s.substring(6, 56))
            .map(s -> s.replaceAll(" ", ""))
            .map(String::toLowerCase)
            .reduce(String::concat);
  }

}
