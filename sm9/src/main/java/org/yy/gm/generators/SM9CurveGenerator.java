package org.yy.gm.generators;

import org.yy.gm.params.SM9CurveParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.Point;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyElement;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyField;
import it.unisa.dia.gas.plaf.jpbc.field.quadratic.QuadraticField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

/**
 * SM9曲线生成器。
 *
 * @author yaoyuan
 * @since 2023/3/9 21:26
 */
public class SM9CurveGenerator extends TypeFCurveGenerator {
    public SM9CurveGenerator(SecureRandom random) {
        super(random, SM9CurveParameters.rBits);
    }

    public SM9CurveGenerator() {
        super(SM9CurveParameters.rBits);
    }

    @Override
    public PairingParameters generate() {
        //先随机生成t，然后计算q和r。这里不需要

        Field Fq = new ZrField(random, SM9CurveParameters.q);

        //生成b。这里不需要

        //beta: TypeF中取的 Fq.getNqr()，即非二次剩余。这里须构造
        BigInteger beta = Fq.newElement(SM9CurveParameters.BETA).toBigInteger();

        Field Fq2 = new QuadraticField(random, Fq);
        PolyField Fq2x = new PolyField(random, Fq2);

        //alpha: TypeF中是随机生成以得到alpha参数；而对于SM9则在这里设置
        //找出一个形如  f = x^6 + alpha 的不可约多项式。
        //把 x^6 的系数设置1，然后代入点(1,0)，就可以计算出alpha。
        PolyElement<Point> f = Fq2x.newElement();
        f.ensureSize(7);
        f.getCoefficient(6).setToOne();

        Point point = (Point) Fq2.newElement();
        point.getX().setToZero();
        point.getY().setToOne();
        f.getCoefficient(0).set(point.negate());

        //存放曲线标准参数
        PropertiesParameters params = new PropertiesParameters();
        params.put("type", "f");
        params.put("q", SM9CurveParameters.q.toString());
        params.put("r", SM9CurveParameters.N.toString());
        params.put("b", SM9CurveParameters.b.toString());
        params.put("beta", beta.toString());
        params.put("alpha0", f.getCoefficient(0).getX().toBigInteger().toString());
        params.put("alpha1", f.getCoefficient(0).getY().toBigInteger().toString());
        params.put("t", SM9CurveParameters.t.toString());

        return params;
    }
}
