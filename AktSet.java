package soot.jimple.infoflow;

import java.util.HashMap;
import java.util.List;

import soot.Value;
import soot.jimple.StringConstant;
import soot.jimple.internal.JInstanceFieldRef;

public class AktSet {
	public class Comparison<X, Y> {
		public final X x;
		public final Y y;
		public boolean isConstantComp;

		public Comparison(X x, Y y, boolean b) {
			this.x = x;
			this.y = y;
			this.isConstantComp = b;
		}
	}

	String booleanExpression;
	HashMap<Value, Value> intentProps;
	HashMap<Value, Value> strConsts;
	HashMap<Value, Comparison<Value, Value>> intentPropCmps;

	public AktSet() {
		intentProps = new HashMap<Value, Value>();
		strConsts = new HashMap<Value, Value>();
		intentPropCmps = new HashMap<Value, Comparison<Value, Value>>();
		booleanExpression = "";
	}

	public void addIntentProperty(Value left, Value right) {
		if (left instanceof JInstanceFieldRef) {
			JInstanceFieldRef jifr = (JInstanceFieldRef) left;
			left = jifr.getBase();
		}
		intentProps.put(left, right);
	}

	public Comparison<Value, Value> getIntentPropertyCmp(Value local) {
		return intentPropCmps.get(local);
	}

	public void addStringConstant(Value left, Value right) {
		strConsts.put(left, right);
	}

	public void addIntentPropertyAlias(Value left, Value right) {
		intentProps.put(left, intentProps.get(right));
	}

	public void addStringConstantAlias(Value left, Value right) {
		strConsts.put(left, strConsts.get(right));
	}

	public boolean isStringConstant(Value val) {
		return strConsts.containsKey(val);
	}

	public boolean isIntentPropertyCmp(Value val) {
		return intentPropCmps.containsKey(val);
	}

	public boolean isIntentProperty(Value val) {
		if (val instanceof JInstanceFieldRef) {
			JInstanceFieldRef jifr = (JInstanceFieldRef) val;
			val = jifr.getBase();
		}
		return intentProps.containsKey(val);
	}

	public void copy(AktSet other) {
		other.clear();
		other.booleanExpression = this.booleanExpression;
		other.intentProps.putAll(this.intentProps);
		other.strConsts.putAll(this.strConsts);
		other.intentPropCmps.putAll(this.intentPropCmps);
	}

	public void merge(AktSet other, AktSet out) {
		out.clear();
		// if (this.booleanExpression.length() > 0
		// || other.booleanExpression.length() > 0) {
		// System.out.println("MERGE:");
		// System.out.println(this.booleanExpression);
		// System.out.println(other.booleanExpression);
		// }

		out.intentProps.putAll(this.intentProps);
		out.strConsts.putAll(this.strConsts);
		out.intentPropCmps.putAll(this.intentPropCmps);
		out.intentProps.putAll(other.intentProps);
		out.strConsts.putAll(other.strConsts);
		out.intentPropCmps.putAll(other.intentPropCmps);
	}

	public void clear() {
		this.intentProps.clear();
		this.strConsts.clear();
	}

	public void processComparison(Value dest, Value left, Value right) {
		Comparison<Value, Value> tup;
		if (this.intentProps.containsKey(left)) {
			Value ip = this.intentProps.get(left);
			if (right instanceof StringConstant) {
				tup = new Comparison<Value, Value>(ip, right, true);
				this.intentPropCmps.put(dest, tup);
			} else if (this.strConsts.containsKey(right)) {
				tup = new Comparison<Value, Value>(ip,
						this.strConsts.get(right), true);
				this.intentPropCmps.put(dest, tup);
			} else {
				tup = new Comparison<Value, Value>(ip, right, false);
				this.intentPropCmps.put(dest, tup);
			}
		} else if (this.intentProps.containsKey(right)) {
			Value ip = this.intentProps.get(right);
			if (left instanceof StringConstant) {
				tup = new Comparison<Value, Value>(ip, left, true);
				this.intentPropCmps.put(dest, tup);
			} else if (this.strConsts.containsKey(left)) {
				tup = new Comparison<Value, Value>(ip,
						this.strConsts.get(left), true);
				this.intentPropCmps.put(dest, tup);
			} else {
				tup = new Comparison<Value, Value>(ip, left, false);
				this.intentPropCmps.put(dest, tup);
			}
		}
	}

	@Override
	public int hashCode() {
		return 0;
	}

	@Override
	public boolean equals(Object obj) {
		return true;
	}

	public Value getIntentProperty(Value val) {
		return this.intentProps.get(val);
	}
}