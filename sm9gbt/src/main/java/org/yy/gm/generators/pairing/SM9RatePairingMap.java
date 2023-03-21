package org.yy.gm.generators.pairing;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Point;
import it.unisa.dia.gas.jpbc.Polynomial;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import it.unisa.dia.gas.plaf.jpbc.pairing.map.AbstractPairingMap;

/**
 * SM9 R-ate.
 *
 * @author yaoyuan
 * @since 2023/3/9 22:29
 */
public class SM9RatePairingMap extends AbstractPairingMap {
    protected SM9Pairing pairingData;
    protected BigInteger a; //pairing计算时用作输入参数

    protected SM9RatePairingMap(SM9Pairing pairing, BigInteger a) {
        super(pairing);
        this.pairingData = pairing;
        this.a = a;
    }

    @Override
    public Element pairing(Point P, Point Q) {
        //参考SM9标准C.6.2
        Point t = (Point) Q.duplicate();
        Polynomial f = (Polynomial) pairingData.getFq12().newOneElement();

        for (int i = a.bitLength() - 2; i >= 0; i--) {
            f.square();
            f.mul(line(t, P));
            t.add(t);
            if (a.testBit(i)) {
                f.mul(line(t, Q, P));
                t.add(Q);
            }
        }

        Point Q11 = fobasmiracl(Q);
        Point Q22 = fobasmiracl(Q11);
        f.mul(line(t, Q11, P));
        t.add(Q11);
        f.mul(line(t, (Point) Q22.negate(), P));
        t.sub(Q22);
        BigInteger q = pairingData.getQ();
        Element e = f.duplicate().pow(q.pow(12).subtract(BigInteger.ONE).divide(pairingData.getN()));

        return new GTFiniteElement(this, (GTFiniteField) pairingData.getGT(), e);
    }

    @Override
    public void finalPow(Element element) {
        //未使用，未实现
    }


    /**
     * @param A point at E(Fp2)
     * @param B point at E(Fp2)
     * @param C point at E(Fp)
     * @return Fp12 Element
     */
    private Element line(Point A, Point B, Point C) {
        Element ax = A.getX().duplicate();
        Element ay = A.getY().duplicate();
        Element bx = B.getX().duplicate();
        Element by = B.getY().duplicate();
        Element cx = C.getX().duplicate();
        Element cy = C.getY().duplicate();
        Point lamda = (Point) ax.getField().newElement();
        lamda = (Point) ay.duplicate().sub(by).div(ax.duplicate().sub(bx));
        Element cof3 = by.duplicate().sub(lamda.duplicate().mul(bx));
        Element cof5 = lamda.duplicate().mulZn(cx);

        Polynomial result = pairingData.getFq12().newElement();
        Element betaInvert = pairingData.getNegAlphaInv();

        Point tempfp2 = (Point) ax.getField().newElement();
        tempfp2.getX().set(cy.negate());
        tempfp2.getY().setToZero();

        result.getCoefficient(0).set(tempfp2);
        result.getCoefficient(3).set(cof3.mul(betaInvert));
        result.getCoefficient(5).set(cof5.mul(betaInvert));

        return result;
    }

    private Element line(Point A, Point C) {
        Element ax = A.getX().duplicate();
        Element ay = A.getY().duplicate();
        Element cx = C.getX().duplicate();
        Element cy = C.getY().duplicate();

        Element lamda = ax.getField().newElement();
        lamda = ax.duplicate().square().mul(3).div(ay.duplicate().mul(2));

        Element cof3 = ay.duplicate().sub(lamda.duplicate().mul(ax));
        Element cof5 = lamda.duplicate().mulZn(cx);

        Polynomial result = pairingData.getFq12().newElement();
        Element betaInvert = pairingData.getNegAlphaInv();

        Point tempfp2 = (Point) ax.getField().newElement();
        tempfp2.getX().set(cy.negate());
        tempfp2.getY().setToZero();

        result.getCoefficient(0).set(tempfp2);
        result.getCoefficient(3).set(cof3.mul(betaInvert));
        result.getCoefficient(5).set(cof5.mul(betaInvert));

        return result;

    }

    private Point fobasmiracl(Point point) {
        Point px = (Point) point.getX().duplicate();
        Point py = (Point) point.getY().duplicate();

        BigInteger q = pairingData.getQ();
        //x the frob constant
        Point x = (Point) pairingData.getFq2().newElement();
        x.getX().setToZero();
        x.getY().setToOne();
        // System.out.println(q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(6)).toString(16));
        x.pow(q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(6)));

        Point w, r;
        r = (Point) x.duplicate().invert();
        w = (Point) r.duplicate().square();

        px.getY().negate();
        px.mul(w);

        py.getY().negate();
        py.mul(w).mul(r);

        Point result = (Point) point.getField().newRandomElement();
        result.getX().set(px);
        result.getY().set(py);
        return result;
    }
}
