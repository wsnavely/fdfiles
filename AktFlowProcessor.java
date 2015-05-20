package soot.jimple.infoflow;

import soot.SootMethod;

public abstract class AktFlowProcessor {
	public abstract boolean isIntentPropertyGetter(SootMethod sm);

	public abstract boolean isIntentSource(SootMethod sm);
}
