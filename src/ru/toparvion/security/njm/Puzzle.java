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

import ru.toparvion.security.njm.proc.DhLogTreeProcessor;
import ru.toparvion.security.njm.proc.LogTreeProcessor;
import ru.toparvion.security.njm.proc.RsaLogTreeProcessor;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Main class of the utility. Contains entry point method main().
 * "Puzzle" is an internal title of the utility project.
 */
public class Puzzle {
  private static final Logger logger = Logger.getLogger(Puzzle.class.getName());
  private static final String PROGRAM_TITLE = String.format("%s v%s",
          Puzzle.class.getPackage().getImplementationTitle(),
          Puzzle.class.getPackage().getImplementationVersion());

  public static void main(String[] args) throws Exception {
    System.out.println(PROGRAM_TITLE);
    if (args.length < 1) {
      System.out.println(USAGE_HINT);
      return;
    }

    String input = args[args.length - 1];
    if (input.toLowerCase().startsWith("-out:") || input.toLowerCase().startsWith("-outmode:")) {
      throw new IllegalArgumentException("Input log file is not specified. Please specify it" +
              " with the -in: option, e.g. -in:somedir/ssl.log.");
    }

    String output = Stream.of(args)
            .filter(s -> s.toLowerCase().startsWith("-out:"))
            .map(s -> s.substring("-out:".length()))
            .findFirst()
            .orElse("session-keys.nss");

    OutMode outMode = Stream.of(args)
            .filter(s -> s.toLowerCase().startsWith("-outmode:"))
            .map(s1 -> s1.substring("-outmode:".length()).toUpperCase())
            .filter(s2 ->
                    Stream.of(OutMode.values())
                            .map(Enum::name)
                            .filter(name -> name.equalsIgnoreCase(s2))
                            .findFirst()
                            .isPresent())
            .map(OutMode::valueOf)
            .findFirst()
            .orElse(OutMode.SKIP);

    Charset inputCharset = Stream.of(args)
            .filter(s -> s.toLowerCase().startsWith("-encoding:"))
            .map(s -> s.substring("-encoding:".length()))
            .map(Charset::forName)
            .findFirst()
            .orElse(Charset.defaultCharset());


    logger.info(String.format("Program start params:\ninput log file: '%s',\ninput encoding: '%s',\noutput NSS file: " +
            "'%s',\noutput file mode: %s.", input, inputCharset.displayName(), output, outMode));

    new Puzzle(input, inputCharset, output, outMode);

  }

  private Puzzle(String input, Charset inputCharset, String output, OutMode outMode) throws Exception {
    // get in and out file paths
    Path logPath = getLogPath(input);
    Path nssPath = getNssPath(output, outMode);

    // build a tree for convenient content processing
    LogTree logTree = parseLogToTree(logPath, inputCharset);
    List<NssFileEntry> entries = new ArrayList<>();
    for (Node branchOrigin : logTree.nodesLevel_0) {
      try {
        // detect the encrypting mode used in the session
        boolean isDhMode = logTree.get(branchOrigin, "ServerKeyExchange", null).isPresent();

        // select and instantiate log tree processor
        LogTreeProcessor processor;
        if (isDhMode) {
          logger.info("Recognized key exchange mode: Diffie-Hellman.");
          processor = new DhLogTreeProcessor();
        } else {
          logger.info("Recognized key exchange mode: RSA.");
          processor = new RsaLogTreeProcessor();
        }

        // make the processor produce NSS file entry
        NssFileEntry nssFileEntry = processor.process(branchOrigin, logTree);
        logger.info("Composed NSS file entry:\n" + nssFileEntry);
        entries.add(nssFileEntry);
      } catch (Exception e) {
        logger.warning(e.getMessage());
      }
    }

    // compose new NSS file lines
    List<String> nssLines = new ArrayList<>(entries.size() + 1);
    nssLines.add(String.format("# SSL/TLS secrets log file, generated by %s (%s)", PROGRAM_TITLE, new Date().toString()));
    nssLines.addAll(entries.stream()
            .map(NssFileEntry::toString)
            .collect(Collectors.toList()));
    // output the results in chosen mode
    Files.write(nssPath, nssLines, outMode.openOptions);
    logger.info("SSL/TLS keys successfully extracted and exported to NSS file: " + output);
  }

  /**
   * Reads log file and fills a 4-level tree with its content.
   */
  private LogTree parseLogToTree(Path logPath, Charset inputCharset) throws IOException {
    LogTree logTree = new LogTree();
    Files.lines(logPath, inputCharset)
            .forEach(token -> {
              if (LogTree.PREDICATE_LEVEL_0.test(token)) {
                Node newNodeLevel_0 = new Node(token);
                logTree.nodesLevel_0.add(newNodeLevel_0);
                logTree.root.getChildren().add(newNodeLevel_0);
                // quite a hack: explicit duplicating this node in order to make it both a marker and a payload node
                Node newNodeLevel_1 = new Node(token);
                logTree.nodesLevel_1.add(newNodeLevel_1);
                newNodeLevel_0.getChildren().add(newNodeLevel_1);
                return;
              }

              if (LogTree.PREDICATE_LEVEL_1.test(token)) {
                Node newNodeLevel_1 = new Node(token);
                logTree.nodesLevel_1.add(newNodeLevel_1);
                logTree.nodesLevel_0.getLast().getChildren().add(newNodeLevel_1);
                return;
              }

              if (LogTree.PREDICATE_LEVEL_2.test(token)) {
                if (!logTree.nodesLevel_1.isEmpty()) {
                  Node newNodeLevel_2 = new Node(token);
                  logTree.nodesLevel_2.add(newNodeLevel_2);
                  logTree.nodesLevel_1.getLast().getChildren().add(newNodeLevel_2);
                } else {
                  logger.fine(String.format("String '%s' has no parent node and thus will be skipped.", token));
                }
                return;
              }

              if (LogTree.PREDICATE_LEVEL_3.test(token)) {
                if (!logTree.nodesLevel_2.isEmpty()) {
                  Node newNodeLevel_3 = new Node(token);
                  logTree.nodesLevel_3.add(newNodeLevel_3);
                  logTree.nodesLevel_2.getLast().getChildren().add(newNodeLevel_3);
                } else {
                  logger.fine(String.format("String '%s' has no parent node and thus will be skipped.", token));
                }
                return;
              }

              logger.warning(String.format("Line '%s' hasn't matched to any log tree level " +
                      "and will be skipped.", token));
            });
    return logTree;
  }

  private static Path getLogPath(String log) throws FileNotFoundException {
    Path logPath = Paths.get(log);
    if (Files.notExists(logPath) || !Files.isReadable(logPath)) {
      throw new FileNotFoundException(String.format("No log file found in '%s' or it is not accessible for reading.",
              logPath.toString()));
    }
    return logPath;
  }

  private static Path getNssPath(String nss, OutMode outMode) {
    Path nssPath = Paths.get(nss);
    if (OutMode.SKIP.equals(outMode) && Files.exists(nssPath)) {
      throw new IllegalArgumentException(String.format("File '%s' already exists. Please choose another output file" +
              " (with -out: option) or set another output mode, e.g. REWRITE or APPEND, with -outMode: option", nss));
    }
    return nssPath;
  }

  /**
   * Enumeration of supported output modes. Every mode includes corresponding OpenOption to use in file handling.
   */
  private enum OutMode {
    APPEND    (StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.APPEND),
    REWRITE   (StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING),
    SKIP;

    OutMode(OpenOption... openOptions) {
      this.openOptions = openOptions;
    }

    OpenOption[] openOptions;
  }

  private static final String USAGE_HINT = "Usage: NssJavaMaker.jar [opts] <path/to/java/ssl/log.file>\n" +
          "Where 'opts':\n" +
          "-out:path/to/result.nss - specifies the path to export the results to, defaults to 'session-keys.nss' in current directory;\n" +
          "                          example: -out:export/session-5.nss;\n" +
          "-outMode:<SKIP|APPEND|REWRITE> - specifies file access mode for exporting results, defaults to SKIP (don't export at all);\n" +
          "                          example: -outMode:APPEND;\n" +
          "-encoding:<encoding_name> - specifies the encoding of input log file; defaults to JVM default encoding;\n" +
          "                          example: -encoding:CP1251.";
}
