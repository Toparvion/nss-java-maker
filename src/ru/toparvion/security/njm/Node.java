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
