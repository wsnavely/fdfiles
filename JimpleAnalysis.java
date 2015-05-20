package soot.jimple.infoflow;

import java.util.List;

import soot.Unit;
import soot.jimple.AssignStmt;
import soot.jimple.EnterMonitorStmt;
import soot.jimple.ExitMonitorStmt;
import soot.jimple.GotoStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.IfStmt;
import soot.jimple.InvokeStmt;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.NopStmt;
import soot.jimple.RetStmt;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.TableSwitchStmt;
import soot.jimple.ThrowStmt;
import soot.tagkit.AttributeValueException;
import soot.tagkit.Tag;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardBranchedFlowAnalysis;

public abstract class JimpleAnalysis extends
		ForwardBranchedFlowAnalysis<AktSet> {

	public JimpleAnalysis(UnitGraph graph) {
		super(graph);
	}

	protected void flowThroughNop(AktSet in, NopStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughIdentity(AktSet in, IdentityStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughAssign(AktSet in, AssignStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughIf(AktSet in, IfStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughGoto(AktSet in, GotoStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughTableSwitch(AktSet in, TableSwitchStmt stmt,
			List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughLookupSwitch(AktSet in, LookupSwitchStmt stmt,
			List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughInvoke(AktSet in, InvokeStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughReturn(AktSet in, ReturnStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughReturnVoid(AktSet in, ReturnVoidStmt stmt,
			List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughEnterMonitor(AktSet in, EnterMonitorStmt stmt,
			List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughExitMonitor(AktSet in, ExitMonitorStmt stmt,
			List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughThrow(AktSet in, ThrowStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	protected void flowThroughRet(AktSet in, RetStmt stmt, List<AktSet> fallOut, List<AktSet> branchOuts) {
		return;
	}

	@Override
	protected void flowThrough(AktSet in, Unit stmt, List<AktSet> fallOut,
			List<AktSet> branchOuts) {
		for(AktSet s : fallOut) {
			in.copy(s);
		}
		for(AktSet s : branchOuts) {
			in.copy(s);
		}
		if(in.booleanExpression.length() > 0) {
			System.out.println("ADDING TAG: " + stmt);
			stmt.addTag(new Tag() {
				@Override
				public byte[] getValue() throws AttributeValueException {
					return in.booleanExpression.getBytes();
				}
				@Override
				public String getName() {
					return "BooleanExpressionTag";
				}
			});
			System.out.println(stmt.hasTag("BooleanExpressionTag"));
		}
		if (stmt instanceof NopStmt) {
			flowThroughNop(in, (NopStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof IdentityStmt) {
			flowThroughIdentity(in, (IdentityStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof AssignStmt) {
			flowThroughAssign(in, (AssignStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof IfStmt) {
			flowThroughIf(in, (IfStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof GotoStmt) {
			flowThroughGoto(in, (GotoStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof TableSwitchStmt) {
			flowThroughTableSwitch(in, (TableSwitchStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof LookupSwitchStmt) {
			flowThroughLookupSwitch(in, (LookupSwitchStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof InvokeStmt) {
			flowThroughInvoke(in, (InvokeStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof ReturnStmt) {
			flowThroughReturn(in, (ReturnStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof ReturnVoidStmt) {
			flowThroughReturnVoid(in, (ReturnVoidStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof EnterMonitorStmt) {
			flowThroughEnterMonitor(in, (EnterMonitorStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof ExitMonitorStmt) {
			flowThroughExitMonitor(in, (ExitMonitorStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof ThrowStmt) {
			flowThroughThrow(in, (ThrowStmt) stmt, fallOut, branchOuts);
		} else if (stmt instanceof RetStmt) {
			flowThroughRet(in, (RetStmt) stmt, fallOut, branchOuts);
		}
	}

	@Override
	protected AktSet newInitialFlow() {
		return new AktSet();
	}

	@Override
	protected AktSet entryInitialFlow() {
		return new AktSet();
	}

	@Override
	protected void merge(AktSet in1, AktSet in2, AktSet out) {
		in1.merge(in2, out);
	}

	@Override
	protected void copy(AktSet source, AktSet dest) {
		source.copy(dest);
	}

}
