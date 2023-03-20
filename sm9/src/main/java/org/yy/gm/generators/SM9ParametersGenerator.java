package org.yy.gm.generators;

import org.yy.gm.generators.pairing.SM9Pairing;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9Parameters;

import java.io.File;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * SM9参数生成器。
 * <p>
 * 生成SM9参数基类 {@link SM9Parameters}
 * <p>
 * 提供一些列的 createParameters 方法来创建 SM9Parameters 对象。包括从文件读取、即时生成、从固定参数构建。
 *
 * @author yaoyuan
 * @since 2023/3/9 22:27
 */
public class SM9ParametersGenerator {
    private SecureRandom random = new SecureRandom();

    public void init(SecureRandom random) {
        if (random != null)
            this.random = random;
    }

    /**
     * 生成SM9参数。
     * <p>
     * 实时计算。
     */
    public SM9Parameters generateParameters() {
        return generateParameters(new SM9CurveGenerator(random).generate());
    }

    /**
     * 生成SM9参数。
     * <p>
     * 直接使用现有参数来构造，此时只需计算P1和P2。
     *
     * @param parameters 参数。可由 {@link SM9CurveParameters#createPairingParameters()} 获得
     */
    public SM9Parameters generateParameters(PairingParameters parameters) {
        SM9Pairing pairing = new SM9Pairing(random, parameters);
        Element P1 = pairing.getG1().newElementFromBytes(SM9CurveParameters.P1_bytes).getImmutable();
        Element P2 = pairing.getG2().newElementFromBytes(SM9CurveParameters.P2_bytes).getImmutable();
        return new SM9Parameters(random, pairing, P1, P2);
    }

    /**
     * 生成SM9参数。
     *
     * @param parametersPath 参数文件路径。为空时实时生成。
     */
    public SM9Parameters generateParameters(String parametersPath) {
        if (parametersPath != null && (!parametersPath.isEmpty()) && new File(parametersPath).isFile()) {
            PairingParameters pairingParameters = PairingFactory.getPairingParameters(parametersPath);
            return generateParameters(pairingParameters);
        } else
            return generateParameters();
    }

    public static SM9Parameters createParameters() {
        return createParameters(new SecureRandom());
    }

    public static SM9Parameters createParameters(SecureRandom random) {
        SM9ParametersGenerator parametersGenerator = new SM9ParametersGenerator();
        parametersGenerator.init(random);
        return parametersGenerator.generateParameters();
    }

    public static SM9Parameters createParameters(PairingParameters parameters) {
        return createParameters(new SecureRandom(), parameters);
    }

    public static SM9Parameters createParameters(SecureRandom random, PairingParameters parameters) {
        SM9ParametersGenerator parametersGenerator = new SM9ParametersGenerator();
        parametersGenerator.init(random);
        return parametersGenerator.generateParameters(parameters);
    }

    public static SM9Parameters createParameters(String parametersPath) {
        return createParameters(new SecureRandom(), parametersPath);
    }

    public static SM9Parameters createParameters(SecureRandom random, String parametersPath) {
        SM9ParametersGenerator parametersGenerator = new SM9ParametersGenerator();
        parametersGenerator.init(random);
        return parametersGenerator.generateParameters(parametersPath);
    }
}
