>While Java Developers are familiar with the impact of GC pauses, 
they may not realise that allocating object could be sapping throughput by 10x or 
more the GC cost esp for very short-lived objects.

source [Java is Very Fast, If You Don’t Create Many Objects](https://blog.vanillajava.blog/2022/09/java-is-very-fast-if-you-dont-create.html)

Throughput, Average Latency <sup>(Across 16 clients, an event is sent in both directions. The Average Latency = 2 * 16 / throughput)</sup>

| JVM Vendor, Version     | No objects             | One object per event   |
|-------------------------|------------------------|------------------------|
| Azul Zulu 1.8.0_322     | 60.6 M event/s, 528 ns | 36.8 M event/s, 879 ns |
| Azul Zulu 11.0.14.1     | 67.3 M event/s, 476 ns | 45.7 M event/s, 700 ns |
| Azul Zulu 17.0.4.1      | 68.6 M event/s, 467 ns | 50.3 M event/s, 636 ns |
| Azul Zulu 18.0.2.1      | 67.5 M event/s, 474 ns | 49.8 M event/s, 642 ns |
| Oracle OpenJDK 18.0.2.1 | 67.8 M event/s, 472 ns | 50.1 M event/s, 638 ns |

[![Watch the video](https://user-images.githubusercontent.com/29354319/197382477-ce53b8cd-d432-4cd6-8b05-c9b7f93ba164.png)](https://youtu.be/qsybVQ5aDDk?t=1126)

That is why the AdHoc protocol in Java actively uses value packets. Each packet, the information in the fields which fits into 8 bytes (primitive `long` type), is treated as a value packet. Java has no `value type` similar to the C# `struct`, so the only option is using primitives with annotations.
```java
   static @ValuePack long set(char src, @ValuePack long pack) {return (long)(pack & ~(255  << 32) | ((src) & (~0L))   << 32) ;}
```

use  `-encoding UTF-8` command line parametr
