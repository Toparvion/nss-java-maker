# NSS JAVA MAKER
A tiny command-line utility for automated Wireshark SSL key (NSS) files creation from Java SSL debug logs.  
These files can be used to decrypt HTTPS (or any other SSL/TLS) traffic produced by Java application.

:bulb: To catch the idea of how it can be used please refer to [this article](https://xakep.ru/2015/08/14/log-almighty/) (in russian).

## Features

* Both [RSA](http://en.wikipedia.org/wiki/RSA_(cryptosystem)) and [Diffie-Hellman](http://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange) (PFS) negotiation modes support;
* Various `-Djavax.net.debug` argument values support *(the `:data` value suffix is required)*;
* Various logging application's JRE versions support *(from 6 to 8)*;
* Multiple independent consecutive SSL sessions support;
* Customizable output file creation modes: **skip, rewrite, append** *(useful for combining with other tools)*;
* Light-weight pure Java application with no external dependencies *(just JRE)*.

## Download
You can always get the freshest verion of NSS Java Maker on the [latest release page](https://github.com/Toparvion/nss-java-maker/releases/latest).

## System Requirements
NSS Java Maker requires only [**JRE 8+**](http://www.oracle.com/technetwork/java/javase/downloads/2133155) to start.

## Usage
> :warning: Please note that use of this utility __is just one intermediate step__ in the more complex process of Java SSL/TLS traffic decryption. Traffic capturing and SSL debug logging precede this step; Wireshark decrypting follows it. To get familiar with the process in whole please refer to article "[Decrypting Java applications' TLS  traffic via logs](http://habrahabr.ru/post/254205/)" or author's article in [Hacker computer magazine](https://xakep.ru/2015/08/14/log-almighty/) (both in russian).

#### Basic usage
The only thing you should point for *NSS Java Maker* to start is the path to input Java SSL log:
```
java -jar nssjavamaker.jar some/directory/java-ssl-debug.log
```
By default the utility produces output file named **session-keys.nss** in the same directory.

#### Additional options usage
:one: Output file path can be customized with `-out:` option, e.g.:
```
java -jar nssjavamaker.jar -out:export/session-5.nss some/directory/java-ssl-debug.log
```
This time the results will be saved in **session-5.nss** file of the **export** directory (resolved against current working directory).

:two: You can also setup how output file will be treated in case if it already exists. This is defined by `-outMode:` option, e.g.:
```
java -jar nssjavamaker.jar -out:export/session-5.nss -outmode:append some/directory/java-ssl-debug.log
```
Launched this way the utility will append the result to file **export/session-5.nss** if it already exists. In case the option has `SKIP` value the utility will stop running and print appropriate message to console; this is the default behavior. The last value for the `-outMode:` option is `REWRITE` which means erasing all the previous content of output file and filling it with the last launch results.

:three: In case your input log file contains some national characters which are not well treated with JVM's default charset, you may need to specify the input file encoding with the `-encoding:` option:
```
java -jar nssjavamaker.jar -encoding:CP1253 some/directory/some-foreign-dump.log
```
Being set to `CP1253` the input log file will be treated by the utility with the specified encoding, not JVM's default. The value of the option is just usual canonical name or alias of appropriate charset.

:information_source: Remember that you can always get a short usage help if you start NSS Java Maker with no arguments.

## Limitations
In the current version *NSS Java Maker* has the following limitations:

* Multi-threaded SSL/TLS communication logs are not supported.  
It means that if your Java application writes log from several simultaneously running threads (each with SSL activity) then proper result are not guaranteed.
* `:data`-disabled log mode are not supported.   
It means that NSS Java Maker would not be able to extract SSL key parameters from log in case of hex dumps' absence (when `:data` part of `jaxav.net.debug` option is not set).

## Feedback & contacts
If you found a bug or need a feature in the utility please feel free to create issues in the project's repository or contact the author directly: toparvion@gmx.com.
