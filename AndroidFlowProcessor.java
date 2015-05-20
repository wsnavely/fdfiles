package soot.jimple.infoflow;

import soot.SootClass;
import soot.SootMethod;

public class AndroidFlowProcessor extends AktFlowProcessor {
	@Override
	public boolean isIntentPropertyGetter(SootMethod sm) {
		SootClass sc = sm.getDeclaringClass();
		String className = sc.getName();
		String methodName = sm.getName();

		if (className.equals("android.content.Intent")) {
			if (methodName.equals("getAction")) {
				return true;
			}
			if(methodName.startsWith("get")) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isIntentSource(SootMethod sm) {
		SootClass sc = sm.getDeclaringClass();
		String className = sc.getName();
		String methodName = sm.getName();
		if (className.equals("android.app.Activity")) {
			if (methodName.equals("startActivityForResult")) {
				return true;
			}
		}
		return false;
	}
}
