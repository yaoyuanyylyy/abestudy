package org.yy.gm.structs;

import org.yy.gm.cipher.AlgDigest;
import org.yy.gm.cipher.AlgSymm;

/**
 * SM9配置文件。
 * <p>
 * 放置SM9中可以修改的配置。
 * <p>
 * 允许配置SM9中用到的哈希算法和对称算法，且相关的一切都从这里出去。
 * 当然默认使用的SM3和SM4，也没有修改的必要，这里仅用作算法扩展。
 * <p>
 * 允许配置私钥生成函数识别符hid，在GMT的SM9标准中签名、密钥交换、加密分别使用1,2,3；在GBT标准中，密钥交换也是用了3。
 * 这里默认配置为GBT标准，但总的来说，应该可以设置为自己想要的值，所以放在这个配置类中，使其可以随意配置。
 * <p>
 * 注意：在某些版本的jdk中，有一部分的对称算法(如AES192, AES256)是受到出口限制，导致不能使用。此时可以通过下载特定的包来覆盖解决；
 * 也可以使用特定版本的jdk，比如 jdk1.8.0_221 版本就不受限制；另外也可以不使用那些受限的对称算法。
 *
 * @author yaoyuan
 * @since 2023/3/18 13:40
 */
public class SM9Config {
    /** SM9用到的哈希算法，默认为SM3，可修改。 */
    public static AlgDigest algDigest = AlgDigest.SM3;

    /** SM9用到的对称算法，默认为SM4，可修改。 */
    public static AlgSymm algSymm = AlgSymm.SM4;

    /**
     * SM9用到的对称算法的填充模式，默认为PKCS5Padding。
     * 可修改为无填充或其他填充模式，但要注意无填充时ECB/CBC要求数据长度必须对其到分组长度，
     * 这样一来似乎复杂化了，所以可以不用修改，就使用默认的填充方式。
     */
    public static String PADDING = "PKCS5Padding";

    /**
     * MAC函数 {@link org.yy.gm.SM9Utils#MAC(byte[] key, byte[] data)} 的密钥key的长度。
     * 按照MAC函数定义来说，这个长度是可以变的，但最好不小于MAC函数中的哈希函数的哈希值长度。
     * 这里默认是32字节，当然也可以自行修改。
     */
    public static int MAC_KEY_LEN = 32;

    /** 在GBT标准的测试中，加密中使用了CBC模式，但IV全是0。该参数可以配置是否要生成一个随机IV，默认为否。可修改。 */
    public static boolean USE_RANDOM_IV = false;

    /** hid：签名私钥生成函数识别符 */
    public static byte HID_SIGN = 0x01;
    /** hid：密钥交换时的私钥生成函数识别符 */
    public static byte HID_KEY_EXCHANGE = 0x03;
    /** hid：加密私钥生成函数识别符 */
    public static byte HID_ENCRYPT = 0x03;

}
