# NSS JAVA MAKER
A tiny command-line utility for automated Wireshark SSL key (NSS) files creation from Java SSL debug logs.  
These files can be used to decrypt HTTPS (or any other SSL/TLS) traffic produced by Java application.

To catch the idea of how it can be used please refer to article "[Decrypting Java applications' TLS  traffic via logs](http://habrahabr.ru/post/254205/)" (in russian).

## Features

* Both [RSA](http://en.wikipedia.org/wiki/RSA_(cryptosystem)) and [Diffie-Hellman](http://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange) (PFC) negotiation modes support;
* Various `-Djavax.net.debug` argument values support *(the `:data` value suffix is required)*;
* Various JRE versions of logging application support *(from 6 to 8)*;
* Customizable output file creation modes: **skip, rewrite, append** *(useful for combining with other tools)*;
* Light-weight pure Java application with no external dependencies *(just JRE)*.

## Download
Besides cloning project's repository you can [download ready-to-work JAR](https://github.com/Toparvion/nss-java-maker/raw/master/download/NssJavaMaker.jar) package of the utility.

## System Requirements
NSS Java Maker requires only [**JRE 8+**](http://www.oracle.com/technetwork/java/javase/downloads/2133155) to start.

## Usage
> Please note that use of this utility __is just one intermediate step__ in the more complex process of Java SSL/TLS traffic decryption. Traffic capturing and SSL debug logging precede this step; Wireshark decrypting follows it. To get familiar with the process in whole please refer to article "[Decrypting Java applications' TLS  traffic via logs](http://habrahabr.ru/post/254205/)" (in russian).

#### Basic usage
The only thing you should set for *NSS Java Maker* to start is the path to input Java SSL log:
```
java -jar nssjavamaker.jar some/directory/java-ssl-debug.log
```
By default the utility produces output file named **session-keys.nss** in the same directory.

#### Options usage
Output file can be customized with `-out:` option, e.g.:
```
java -jar nssjavamaker.jar -out:export/session-5.nss some/directory/java-ssl-debug.log
```
This time the results will be saved in **session-5.nss** file of the **export** directory.

You can also setup how output file will be treated in case if it already exists. This is defined by `-outMode:` option, e.g.:
```
java -jar nssjavamaker.jar -out:export/session-5.nss -outmode:append some/directory/java-ssl-debug.log
```
Launched this way the utility will append the result to file **export/session-5.nss** if it already exists. In case the option has `SKIP` value the utility will stop running and print appropriate message in console; this is the default behavior. The last value for the `-outMode:` option is `REWRITE` which means erasing all the previous content of output file and filling it with the last launch results.

## Limitations
In the current version *NSS Java Maker* has the following limitations:

* Only first block of SSL debug records is processed.  
It means that if your log contains records from several consequent SSL/TLS sessions then only the first one will be processed by the utility. In order to process such log properly please split it into several files and launch the utility for each of them.

* Multi-threaded SSL/TLS communication logs are not supported.  
It means that if your Java application writes log from several simultaneously running threads (each with SSL activity) then proper result are not guaranteed.

## Feedback & contacts
If you found a bug or need a feature in the utility please feel free to create issues in project's repository or contact the author directly: toparvion@gmx.com.
