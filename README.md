
[toc]

# 算法学习研究项目

# 说明

本项目仅用于自我学习，实现了一些密码算法，包括但不限于SM9、IBE、ABE。

开发工具使用 IDEA-2022.2，JDK-1.8-221，使用maven管理JPBC和BC密码库。

算法实现的代码结构参考了 jpbc-crypto 中的算法实现。

目前包含的算法：

- 

# jpbc

## jpbc-crypto 算法代码结构

参考 jpbc-crypto 中属性基加密算法 GGHSW13 的实现，可以看出它的结构特点：

- generators中是**生成器类**。如密钥对生成器、参数生成器、秘密密钥生成器等。
- engines中是算法实现**引擎类**。如KEMEngine可用来实现密钥封装解封或加密解密。
- params中是算法**参数类**。算法中的生成器、引擎类需要的参数都放在这里。
  生成器和引擎类一般通过 init 方法来初始化要使用的参数，所以需要把某个算法中用到的参数都放置在一个参数类中进行传递。
  比如密钥对生成器 GGHSW13SecretKeyGenerator 秘密密钥生成器中要用到的参数都封装在 GGHSW13SecretKeyGenerationParameters 中。 
- 最后在一个**算法类** GGHSW13KEM 中实现论文里提出的算法构造步骤，如 setup、keyGen等。这才是应该使用的算法对象。

## maven 配置 jpbc

项目中主要使用到了 jpbc 中的 `api`、`plaf`、`crypto`这3个库，它们又依赖了 `bcprov` 库。

1. 本地库方式
   可以直接在项目中使用下面的方式配置本地库。
   但由于父项目的本地依赖中的 `systemPath` 无法传递到子项目去，所以需要为每个项目都配置一下。

        ```xml
        <dependency>
            <groupId>it.unisa.dia.gas</groupId>
            <artifactId>jpbc-api</artifactId>
            <version>2.0.0</version>
            <scope>system</scope>
            <systemPath>${pom.basedir}/libs/jpbc-api-2.0.0.jar</systemPath>
        </dependency>

        <dependency>
            <groupId>it.unisa.dia.gas</groupId>
            <artifactId>jpbc-plaf</artifactId>
            <version>2.0.0</version>
            <scope>system</scope>
            <systemPath>${pom.basedir}/libs/jpbc-plaf-2.0.0.jar</systemPath>
        </dependency>

        <dependency>
            <groupId>it.unisa.dia.gas</groupId>
            <artifactId>jpbc-crypto</artifactId>
            <version>2.0.0</version>
            <scope>system</scope>
            <systemPath>${pom.basedir}/libs/jpbc-crypto-2.0.0.jar</systemPath>
        </dependency>

        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
            <version>1.71</version>
            <scope>system</scope>
            <systemPath>${pom.basedir}/libs/bcprov-jdk18on-1.71.jar</systemPath>
        </dependency>
        ```

2. 在线库方式
   也可以使用下面的方式来配置，让maven自动下载。
   这种方式可以只在父项目中配置，然后子项目就可以引用。

        ```xml
        <repositories>
            <repository>
                <id>jitpack.io</id>
                <url>https://www.jitpack.io</url>
                <snapshots>
                    <enabled>true</enabled>
                </snapshots>
            </repository>
        </repositories>

        <dependencies>
            <dependency>
                <groupId>com.github.stefano81</groupId>
                <artifactId>jpbc</artifactId>
                <version>v2.0.0-m</version>
                <exclusions>
                    <exclusion>
                        <groupId>org.bouncycastle</groupId>
                        <artifactId>bcprov-jdk16</artifactId>
                    </exclusion>
                </exclusions>
            </dependency>

            <dependency>
                <groupId>org.bouncycastle</groupId>
                <artifactId>bcprov-jdk18on</artifactId>
                <version>1.71</version>
            </dependency>
        </dependencies>
        ```

   但这种方式又有另外两个问题：

   - 由于 jpbc 引用了 jitpack.io，这会让maven无法从默认的repository中找到jpbc，所以无法下载。特别是在 maven 的 settings.xml 配置了阿里云时，会提示找不到。这时候需要把阿里云的配置中的 `mirrorOf` 修改一下，让其从 jitpack.io 上去找库。如需所示：

        ```xml
        <mirror>
            <id>aliyunmaven</id>
            <mirrorOf>*,!jitpack.io</mirrorOf>
            <name>aliyun-maven</name>
            <url>https://maven.aliyun.com/repository/public</url>
        </mirror>
        ```

   - jpbc中默认使用的BC库版本是 bcprov-jdk16:1.46，这会让IDEA提示“Provides transitive vulnerable dependency”，所以在上面的 jpbc 依赖中添加了 `exclusions` 来排除 `bcprov-jdk16`，然后从小引入依赖 `bcprov-jdk18on`。这个应该和版本有关。

   由于本项目预计包含多个子项目，所以采用第二种方式来配置 jpbc 依赖。因此，需要可能需要修改自己的maven配置文件中的`mirrorOf`。

