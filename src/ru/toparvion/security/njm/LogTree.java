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

  LinkedList<Node> nodesLevel_1 = new LinkedList<>();
  static final Predicate<String> PREDICATE_LEVEL_1 = s -> s.startsWith("*** ");

  LinkedList<Node> nodesLevel_2 = new LinkedList<>();
  static final Predicate<String> PREDICATE_LEVEL_2 = RAW_DATA_LINE_REGEXP.asPredicate().negate();

  LinkedList<Node> nodesLevel_3 = new LinkedList<>();
  static final Predicate<String> PREDICATE_LEVEL_3 = RAW_DATA_LINE_REGEXP.asPredicate();

  Node root = new Node("root", new ArrayList<>(nodesLevel_1));

  /**
   * Traverses the tree through specified levels' tokens and returns third level nodes' content (HEX dump), if found.
   * @param level_1 first level token; must not be <code>null</code>
   * @param level_2 second level token; may be <code>null</code>
   * @param level_3 third level tokens (several tokens mean returning the concatenation of all matched nodes); may be
   *                <code>null</code>
   * @return found nodes content, if any
   */
  public Optional<String> get(String level_1, String level_2, String... level_3) {
    Optional<Node> nodeLevel_1 = nodesLevel_1.stream()
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
