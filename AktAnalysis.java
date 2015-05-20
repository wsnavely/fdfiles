package soot.jimple.infoflow;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.AssignStmt;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.StringConstant;
import soot.jimple.internal.AbstractBinopExpr;
import soot.jimple.internal.JEqExpr;
import soot.jimple.internal.JNeExpr;
import soot.toolkits.graph.UnitGraph;
import soot.jimple.infoflow.AktFlowProcessor;
import soot.jimple.infoflow.AktSet;
import soot.jimple.infoflow.AktSet.Comparison;
import soot.jimple.infoflow.AndroidFlowProcessor;
import soot.jimple.infoflow.Debug;
import soot.jimple.infoflow.JimpleAnalysis;

public class AktAnalysis extends JimpleAnalysis {

	private AktFlowProcessor fp;

	public AktAnalysis(UnitGraph graph) {
		super(graph);
		fp = new AndroidFlowProcessor();
		doAnalysis();
	}

	@Override
	protected void flowThroughAssign(AktSet in, AssignStmt stmt,
			List<AktSet> fallOut, List<AktSet> branchOuts) {
		Value left = stmt.getLeftOp();
		Value right = stmt.getRightOp();
		AktSet out = fallOut.get(0);

		if (out.isIntentProperty(right)) {
			out.addIntentPropertyAlias(left, right);
			Debug.debugInfo("[AKTION][INTENTALIAS] " + stmt);
		} else if (out.isStringConstant(right)) {
			out.addStringConstantAlias(left, right);
			Debug.debugInfo("[AKTION][STRALIAS] " + stmt);
		} else if (right instanceof StringConstant) {
			out.addStringConstant(left, right);
			Debug.debugInfo("[AKTION][STRSRC] " + stmt);
		} else if (stmt.containsInvokeExpr()) {
			InvokeExpr ie = stmt.getInvokeExpr();
			SootMethod sm = ie.getMethod();
			if (fp.isIntentPropertyGetter(sm)) {
				out.addIntentProperty(left, ie);
				Debug.debugInfo("[AKTION][INTENTSRC] " + stmt);
			} else if (isStringEquals(sm)) {
				Set<ValueBox> boxes = new HashSet<ValueBox>(ie.getUseBoxes());
				ValueBox argBox = ie.getArgBox(0);
				boxes.remove(argBox);
				Value arg = argBox.getValue();
				Value caller = null;
				for (ValueBox v : boxes) {
					caller = v.getValue();
					break;
				}
				out.processComparison(left, arg, caller);
			}
		}
	}

	@Override
	protected void flowThroughIf(AktSet in, IfStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		Value cond = stmt.getCondition();

		if (cond instanceof JEqExpr || cond instanceof JNeExpr) {
			AbstractBinopExpr eq = (AbstractBinopExpr) cond;
			Value left = eq.getOp1();
			Value right = eq.getOp2();
			Comparison<Value, Value> cmp;
			String op = cond instanceof JEqExpr ? "==" : "!=";
			String opNeg = cond instanceof JEqExpr ? "!=" : "==";
			
			if (in.isIntentPropertyCmp(left)) {
				Debug.debugInfo("[AKTION][BRANCH] " + stmt);
				cmp = in.getIntentPropertyCmp(left);
				String expr = String.format("E(%s, %s) %s %s;", fmt(cmp.x),
						fmt(cmp.y), op, fmt(right));
				String exprNeg = String.format("E(%s, %s) %s %s;", fmt(cmp.x),
						fmt(cmp.y), opNeg, fmt(right));
				System.out.println(expr);
				fallOut.get(0).booleanExpression += exprNeg;
				branchOuts.get(0).booleanExpression += expr;
			} else if (in.isIntentPropertyCmp(right)) {
				cmp = in.getIntentPropertyCmp(right);
				System.out.printf("E(%s, %s, %s) %s %s\n", fmt(cmp.x),
						fmt(cmp.y), cmp.isConstantComp, op, fmt(left));
			} else if (in.isIntentProperty(left)) {
				Value ip = in.getIntentProperty(left);
				System.out.printf("%s %s %s\n", fmt(ip), op, fmt(right));
			} else if (in.isIntentProperty(right)) {
				Value ip = in.getIntentProperty(right);
				System.out.printf("%s %s %s\n", fmt(ip), op, fmt(left));
			}
		}
	}

	private String fmt(Value val) {
		if (val instanceof InvokeExpr) {
			InvokeExpr ie = (InvokeExpr) val;
			String method = ie.getMethod().getName();

			String argStr = "";
			boolean first = true;
			for (Value arg : ie.getArgs()) {
				if (first) {
					first = false;
				} else {
					argStr += ",";
				}
				argStr += arg.toString();
			}

			Set<ValueBox> boxes = new HashSet<ValueBox>(ie.getUseBoxes());
			Value caller = null;
			for (ValueBox v : boxes) {
				caller = v.getValue();
				break;
			}
			return method;
		} else {
			return val.toString();
		}
	}

	private boolean isStringEquals(SootMethod sm) {
		SootClass sc = sm.getDeclaringClass();
		String className = sc.getName();
		String methodName = sm.getName();
		if (className.equals("java.lang.String")) {
			if (methodName.equals("equals")) {
				return true;
			}
		}
		return false;
	}
}
