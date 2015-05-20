/*******************************************************************************
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * 
 * Contributors: Christian Fritz, Steven Arzt, Siegfried Rasthofer, Eric
 * Bodden, and others.
 ******************************************************************************/
package soot.jimple.infoflow;

import heros.solver.CountingThreadPoolExecutor;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.Body;
import soot.Hierarchy;
import soot.MethodOrMethodContext;
import soot.PackManager;
import soot.PatchingChain;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.infoflow.InfoflowResults.SinkInfo;
import soot.jimple.infoflow.InfoflowResults.SourceInfo;
import soot.jimple.infoflow.aliasing.FlowSensitiveAliasStrategy;
import soot.jimple.infoflow.aliasing.IAliasingStrategy;
import soot.jimple.infoflow.aliasing.PtsBasedAliasStrategy;
import soot.jimple.infoflow.config.IInfoflowConfig;
import soot.jimple.infoflow.data.AbstractionAtSink;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.data.pathBuilders.DefaultPathBuilderFactory;
import soot.jimple.infoflow.data.pathBuilders.IAbstractionPathBuilder;
import soot.jimple.infoflow.data.pathBuilders.IPathBuilderFactory;
import soot.jimple.infoflow.entryPointCreators.IEntryPointCreator;
import soot.jimple.infoflow.handlers.ResultsAvailableHandler;
import soot.jimple.infoflow.handlers.TaintPropagationHandler;
import soot.jimple.infoflow.ipc.DefaultIPCManager;
import soot.jimple.infoflow.ipc.IIPCManager;
import soot.jimple.infoflow.problems.BackwardsInfoflowProblem;
import soot.jimple.infoflow.problems.InfoflowProblem;
import soot.jimple.infoflow.solver.BackwardsInfoflowCFG;
import soot.jimple.infoflow.solver.IInfoflowCFG;
import soot.jimple.infoflow.solver.fastSolver.InfoflowSolver;
import soot.jimple.infoflow.source.ISourceSinkManager;
import soot.jimple.infoflow.util.IntentTag;
import soot.jimple.infoflow.util.SootMethodRepresentationParser;
import soot.jimple.infoflow.util.SystemClassHandler;
import soot.jimple.internal.AbstractInvokeExpr;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;

/**
 * main infoflow class which triggers the analysis and offers method to
 * customize it.
 *
 */
public class Infoflow extends AbstractInfoflow {

	private final Logger logger = LoggerFactory.getLogger(getClass());

	private static int accessPathLength = 5;
	private static boolean useRecursiveAccessPaths = true;
	private static boolean pathAgnosticResults = true;

	private InfoflowResults results = null;
	private final IPathBuilderFactory pathBuilderFactory;

	private final String androidPath;
	private final boolean forceAndroidJar;
	private IInfoflowConfig sootConfig;

	private IIPCManager ipcManager = new DefaultIPCManager(
			new ArrayList<String>());

	private IInfoflowCFG iCfg;

	private Set<ResultsAvailableHandler> onResultsAvailable = new HashSet<ResultsAvailableHandler>();
	private Set<TaintPropagationHandler> taintPropagationHandlers = new HashSet<TaintPropagationHandler>();

	/**
	 * Creates a new instance of the InfoFlow class for analyzing plain Java
	 * code without any references to APKs or the Android SDK.
	 */
	public Infoflow() {
		this.androidPath = "";
		this.forceAndroidJar = false;
		this.pathBuilderFactory = new DefaultPathBuilderFactory();
	}

	/**
	 * Creates a new instance of the Infoflow class for analyzing Android APK
	 * files.
	 * 
	 * @param androidPath
	 *            If forceAndroidJar is false, this is the base directory of the
	 *            platform files in the Android SDK. If forceAndroidJar is true,
	 *            this is the full path of a single android.jar file.
	 * @param forceAndroidJar
	 *            True if a single platform JAR file shall be forced, false if
	 *            Soot shall pick the appropriate platform version
	 */
	public Infoflow(String androidPath, boolean forceAndroidJar) {
		super();
		this.androidPath = androidPath;
		this.forceAndroidJar = forceAndroidJar;
		this.pathBuilderFactory = new DefaultPathBuilderFactory();
	}

	/**
	 * Creates a new instance of the Infoflow class for analyzing Android APK
	 * files.
	 * 
	 * @param androidPath
	 *            If forceAndroidJar is false, this is the base directory of the
	 *            platform files in the Android SDK. If forceAndroidJar is true,
	 *            this is the full path of a single android.jar file.
	 * @param forceAndroidJar
	 *            True if a single platform JAR file shall be forced, false if
	 *            Soot shall pick the appropriate platform version
	 * @param icfgFactory
	 *            The interprocedural CFG to be used by the InfoFlowProblem
	 * @param pathBuilderFactory
	 *            The factory class for constructing a path builder algorithm
	 */
	public Infoflow(String androidPath, boolean forceAndroidJar,
			BiDirICFGFactory icfgFactory, IPathBuilderFactory pathBuilderFactory) {
		super(icfgFactory);
		this.androidPath = androidPath;
		this.forceAndroidJar = forceAndroidJar;
		this.pathBuilderFactory = pathBuilderFactory;
	}

	public void setSootConfig(IInfoflowConfig config) {
		sootConfig = config;
	}

	/**
	 * Initializes Soot.
	 * 
	 * @param appPath
	 *            The application path containing the analysis client
	 * @param libPath
	 *            The Soot classpath containing the libraries
	 * @param classes
	 *            The set of classes that shall be checked for data flow
	 *            analysis seeds. All sources in these classes are used as
	 *            seeds.
	 * @param sourcesSinks
	 *            The manager object for identifying sources and sinks
	 */
	private void initializeSoot(String appPath, String libPath,
			Set<String> classes) {
		initializeSoot(appPath, libPath, classes, "");
	}

	/**
	 * Initializes Soot.
	 * 
	 * @param appPath
	 *            The application path containing the analysis client
	 * @param libPath
	 *            The Soot classpath containing the libraries
	 * @param classes
	 *            The set of classes that shall be checked for data flow
	 *            analysis seeds. All sources in these classes are used as
	 *            seeds. If a non-empty extra seed is given, this one is used
	 *            too.
	 */
	private void initializeSoot(String appPath, String libPath,
			Set<String> classes, String extraSeed) {
		// reset Soot:
		logger.info("Resetting Soot...");
		soot.G.reset();

		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		if (logger.isDebugEnabled())
			Options.v().set_output_format(Options.output_format_jimple);
		else
			Options.v().set_output_format(Options.output_format_none);

		// We only need to distinguish between application and library classes
		// if we use the OnTheFly ICFG
		if (callgraphAlgorithm == CallgraphAlgorithm.OnDemand) {
			Options.v().set_soot_classpath(libPath);
			if (appPath != null) {
				List<String> processDirs = new LinkedList<String>();
				for (String ap : appPath.split(File.pathSeparator))
					processDirs.add(ap);
				Options.v().set_process_dir(processDirs);
			}
		} else
			Options.v().set_soot_classpath(
					appPath + File.pathSeparator + libPath);

		// Configure the callgraph algorithm
		switch (callgraphAlgorithm) {
		case AutomaticSelection:
			// If we analyze a distinct entry point which is not static,
			// SPARK fails due to the missing allocation site and we fall
			// back to CHA.
			if (extraSeed == null || extraSeed.isEmpty()) {
				Options.v().setPhaseOption("cg.spark", "on");
				Options.v().setPhaseOption("cg.spark", "string-constants:true");
			} else
				Options.v().setPhaseOption("cg.cha", "on");
			break;
		case CHA:
			Options.v().setPhaseOption("cg.cha", "on");
			break;
		case RTA:
			Options.v().setPhaseOption("cg.spark", "on");
			Options.v().setPhaseOption("cg.spark", "rta:true");
			Options.v().setPhaseOption("cg.spark", "string-constants:true");
			break;
		case VTA:
			Options.v().setPhaseOption("cg.spark", "on");
			Options.v().setPhaseOption("cg.spark", "vta:true");
			Options.v().setPhaseOption("cg.spark", "string-constants:true");
			break;
		case SPARK:
			Options.v().setPhaseOption("cg.spark", "on");
			Options.v().setPhaseOption("cg.spark", "string-constants:true");
			break;
		case OnDemand:
			// nothing to set here
			break;
		default:
			throw new RuntimeException("Invalid callgraph algorithm");
		}

		// Specify additional options required for the callgraph
		if (callgraphAlgorithm != CallgraphAlgorithm.OnDemand) {
			Options.v().set_whole_program(true);
			Options.v().setPhaseOption("cg", "trim-clinit:false");
		}

		// do not merge variables (causes problems with PointsToSets)
		Options.v().setPhaseOption("jb.ulp", "off");

		if (!this.androidPath.isEmpty()) {
			Options.v().set_src_prec(Options.src_prec_apk);
			if (this.forceAndroidJar)
				soot.options.Options.v()
						.set_force_android_jar(this.androidPath);
			else
				soot.options.Options.v().set_android_jars(this.androidPath);
		} else
			Options.v().set_src_prec(Options.src_prec_java);

		// at the end of setting: load user settings:
		if (sootConfig != null)
			sootConfig.setSootOptions(Options.v());

		// load all entryPoint classes with their bodies
		Scene.v().loadNecessaryClasses();
		boolean hasClasses = false;
		for (String className : classes) {
			SootClass c = Scene.v().forceResolve(className, SootClass.BODIES);
			if (c != null) {
				c.setApplicationClass();
				if (!c.isPhantomClass() && !c.isPhantom())
					hasClasses = true;
			}
		}
		if (!hasClasses) {
			logger.error("Only phantom classes loaded, skipping analysis...");
			return;
		}
	}

	@Override
	public void computeInfoflow(String appPath, String libPath,
			IEntryPointCreator entryPointCreator,
			ISourceSinkManager sourcesSinks) {
		if (sourcesSinks == null) {
			logger.error("Sources are empty!");
			return;
		}

		Set<String> requiredClasses = SootMethodRepresentationParser.v()
				.parseClassNames(entryPointCreator.getRequiredClasses(), false)
				.keySet();
		initializeSoot(appPath, libPath, requiredClasses);

		// entryPoints are the entryPoints required by Soot to calculate Graph -
		// if there is no main method,
		// we have to create a new main method and use it as entryPoint and
		// store our real entryPoints
		Scene.v().setEntryPoints(
				Collections.singletonList(entryPointCreator.createDummyMain()));
		ipcManager.updateJimpleForICC();

		addBooleanExpressionTagger();

		// We explicitly select the packs we want to run for performance reasons
		if (callgraphAlgorithm != CallgraphAlgorithm.OnDemand) {
			PackManager.v().getPack("wjpp").apply();
			PackManager.v().getPack("cg").apply();
			//PackManager.v().getPack("wjap").apply();
		}

		PackManager.v().getPack("wjap").apply();
		runAnalysis(sourcesSinks, null);

		if (logger.isDebugEnabled())
			PackManager.v().writeOutput();
	}

	private void addBooleanExpressionTagger() {
		PackManager.v().getPack("wjap")
				.add(new Transform("wjap.myTransform", new SceneTransformer() {

					@Override
					protected void internalTransform(String phaseName,
							Map<String, String> options) {
						for (SootClass sc : Scene.v().getClasses()) {
							for (SootMethod m : sc.getMethods()) {
								try {
									Body b = m.retrieveActiveBody();
									new AktAnalysis(new ExceptionalUnitGraph(b));
								} catch (Exception e) {
									continue;
								}
							}
						}
					}
				}));
	}

	@Override
	public void computeInfoflow(String appPath, String libPath,
			String entryPoint, ISourceSinkManager sourcesSinks) {
		if (sourcesSinks == null) {
			logger.error("Sources are empty!");
			return;
		}

		initializeSoot(appPath, libPath, SootMethodRepresentationParser.v()
				.parseClassNames(Collections.singletonList(entryPoint), false)
				.keySet(), entryPoint);

		if (!Scene.v().containsMethod(entryPoint)) {
			logger.error("Entry point not found: " + entryPoint);
			return;
		}
		SootMethod ep = Scene.v().getMethod(entryPoint);
		if (ep.isConcrete())
			ep.retrieveActiveBody();
		else {
			logger.debug("Skipping non-concrete method " + ep);
			return;
		}
		Scene.v().setEntryPoints(Collections.singletonList(ep));
		Options.v().set_main_class(ep.getDeclaringClass().getName());

		// Compute the additional seeds if they are specified
		Set<String> seeds = Collections.emptySet();
		if (entryPoint != null && !entryPoint.isEmpty())
			seeds = Collections.singleton(entryPoint);

		ipcManager.updateJimpleForICC();
		addBooleanExpressionTagger();

		// We explicitly select the packs we want to run for performance reasons
		if (callgraphAlgorithm != CallgraphAlgorithm.OnDemand) {
			PackManager.v().getPack("wjpp").apply();
			PackManager.v().getPack("cg").apply();
			//PackManager.v().getPack("wjap").apply();
		}

		runAnalysis(sourcesSinks, seeds);
		if (logger.isDebugEnabled())
			PackManager.v().writeOutput();
	}

	private void runAnalysis(final ISourceSinkManager sourcesSinks,
			final Set<String> additionalSeeds) {
		// Run the preprocessors
		for (Transform tr : preProcessors)
			tr.apply();

		if (callgraphAlgorithm != CallgraphAlgorithm.OnDemand)
			logger.info("Callgraph has {} edges", Scene.v().getCallGraph()
					.size());
		iCfg = icfgFactory.buildBiDirICFG(callgraphAlgorithm);

		int numThreads = Runtime.getRuntime().availableProcessors();
		CountingThreadPoolExecutor executor = createExecutor(numThreads);
		CountingThreadPoolExecutor staticExecutor = createExecutor(numThreads);

		BackwardsInfoflowProblem backProblem, staticBackProblem;
		InfoflowSolver backSolver, staticBackSolver;
		final IAliasingStrategy aliasingStrategy, staticAliasingStrategy;
		switch (aliasingAlgorithm) {
		case FlowSensitive:
			backProblem = new BackwardsInfoflowProblem(
					new BackwardsInfoflowCFG(iCfg), sourcesSinks);
			staticBackProblem = new BackwardsInfoflowProblem(
					new BackwardsInfoflowCFG(iCfg), sourcesSinks);
			// need to set this before creating the zero abstraction
			backProblem.setFlowSensitiveAliasing(flowSensitiveAliasing);
			staticBackProblem.setFlowSensitiveAliasing(flowSensitiveAliasing);

			backSolver = new InfoflowSolver(backProblem, executor);
			backSolver.setJumpPredecessors(!computeResultPaths);

			staticBackSolver = new InfoflowSolver(staticBackProblem, executor);
			staticBackSolver.setJumpPredecessors(!computeResultPaths);

			// backSolver.setEnableMergePointChecking(true);

			aliasingStrategy = new FlowSensitiveAliasStrategy(iCfg, backSolver);
			staticAliasingStrategy = new FlowSensitiveAliasStrategy(iCfg,
					staticBackSolver);
			break;
		case PtsBased:
			backProblem = null;
			backSolver = null;
			staticBackProblem = null;
			staticBackSolver = null;
			aliasingStrategy = new PtsBasedAliasStrategy(iCfg);
			staticAliasingStrategy = new PtsBasedAliasStrategy(iCfg);
			break;
		default:
			throw new RuntimeException("Unsupported aliasing algorithm");
		}

		InfoflowProblem forwardProblem = new InfoflowProblem(iCfg,
				sourcesSinks, aliasingStrategy);
		InfoflowProblem staticForwardProblem = new InfoflowProblem(iCfg,
				sourcesSinks, staticAliasingStrategy);

		// need to set this before creating the zero abstraction
		forwardProblem.setFlowSensitiveAliasing(flowSensitiveAliasing);
		staticForwardProblem.setFlowSensitiveAliasing(flowSensitiveAliasing);
		if (backProblem != null)
			forwardProblem.setZeroValue(backProblem.createZeroValue());

		// Set the options
		InfoflowSolver forwardSolver = new InfoflowSolver(forwardProblem,
				executor);
		InfoflowSolver staticForwardSolver = new InfoflowSolver(
				staticForwardProblem, staticExecutor);

		aliasingStrategy.setForwardSolver(forwardSolver);
		forwardSolver.setJumpPredecessors(!computeResultPaths);
		// forwardSolver.setEnableMergePointChecking(true);

		forwardProblem.setInspectSources(inspectSources);
		forwardProblem.setInspectSinks(inspectSinks);
		forwardProblem.setEnableImplicitFlows(enableImplicitFlows);
		forwardProblem.setEnableStaticFieldTracking(enableStaticFields);
		forwardProblem.setEnableExceptionTracking(enableExceptions);
		for (TaintPropagationHandler tp : taintPropagationHandlers)
			forwardProblem.addTaintPropagationHandler(tp);
		forwardProblem.setTaintWrapper(taintWrapper);
		forwardProblem.setStopAfterFirstFlow(stopAfterFirstFlow);
		forwardProblem
				.setIgnoreFlowsInSystemPackages(ignoreFlowsInSystemPackages);

		aliasingStrategy.setForwardSolver(staticForwardSolver);
		staticForwardSolver.setJumpPredecessors(!computeResultPaths);
		// forwardSolver.setEnableMergePointChecking(true);

		staticForwardProblem.setInspectSources(inspectSources);
		staticForwardProblem.setInspectSinks(inspectSinks);
		staticForwardProblem.setEnableImplicitFlows(enableImplicitFlows);
		staticForwardProblem.setEnableStaticFieldTracking(enableStaticFields);
		staticForwardProblem.setEnableExceptionTracking(enableExceptions);
		for (TaintPropagationHandler tp : taintPropagationHandlers)
			staticForwardProblem.addTaintPropagationHandler(tp);

		staticForwardProblem.setTaintWrapper(taintWrapper);
		staticForwardProblem.setStopAfterFirstFlow(stopAfterFirstFlow);
		staticForwardProblem
				.setIgnoreFlowsInSystemPackages(ignoreFlowsInSystemPackages);
		staticForwardProblem.setIdentifyStaticFields(true);

		if (backProblem != null) {
			backProblem.setForwardSolver((InfoflowSolver) forwardSolver);
			backProblem.setTaintWrapper(taintWrapper);
			backProblem.setEnableStaticFieldTracking(enableStaticFields);
			backProblem.setEnableExceptionTracking(enableExceptions);
			for (TaintPropagationHandler tp : taintPropagationHandlers)
				backProblem.addTaintPropagationHandler(tp);
			backProblem.setTaintWrapper(taintWrapper);
			backProblem.setActivationUnitsToCallSites(forwardProblem);
			backProblem
					.setIgnoreFlowsInSystemPackages(ignoreFlowsInSystemPackages);
			backProblem.setInspectSources(inspectSources);
			backProblem.setInspectSinks(inspectSinks);

			staticBackProblem.setForwardSolver((InfoflowSolver) forwardSolver);
			staticBackProblem.setTaintWrapper(taintWrapper);
			staticBackProblem.setEnableStaticFieldTracking(enableStaticFields);
			staticBackProblem.setEnableExceptionTracking(enableExceptions);
			for (TaintPropagationHandler tp : taintPropagationHandlers)
				staticBackProblem.addTaintPropagationHandler(tp);
			staticBackProblem.setTaintWrapper(taintWrapper);
			staticBackProblem.setActivationUnitsToCallSites(forwardProblem);
			staticBackProblem
					.setIgnoreFlowsInSystemPackages(ignoreFlowsInSystemPackages);
			staticBackProblem.setInspectSources(inspectSources);
			staticBackProblem.setInspectSinks(inspectSinks);
		}

		if (!enableStaticFields)
			logger.warn("Static field tracking is disabled, results may be incomplete");
		if (!flowSensitiveAliasing || !aliasingStrategy.isFlowSensitive())
			logger.warn("Using flow-insensitive alias tracking, results may be imprecise");

		// We have to look through the complete program to find sources
		// which are then taken as seeds.
		int sinkCount = 0;
		logger.info("Looking for sources and sinks...");

		for (SootMethod sm : getMethodsForSeeds(iCfg)) {
			sinkCount += scanMethodForSourcesSinks(sourcesSinks,
					forwardProblem, staticForwardProblem, sm);
		}

		// We optionally also allow additional seeds to be specified
		if (additionalSeeds != null)
			for (String meth : additionalSeeds) {
				SootMethod m = Scene.v().getMethod(meth);
				if (!m.hasActiveBody()) {
					logger.warn("Seed method {} has no active body", m);
					continue;
				}
				forwardProblem.addInitialSeeds(m.getActiveBody().getUnits()
						.getFirst(),
						Collections.singleton(forwardProblem.zeroValue()));
			}

		if (!forwardProblem.hasInitialSeeds() || sinkCount == 0) {
			logger.error("No sources or sinks found, aborting analysis");
			return;
		}

		int terminateTries;
		Set<AbstractionAtSink> res;

		logger.info("Starting with the Static Forward Solving...");

		if (staticForwardProblem.hasInitialSeeds() && sinkCount != 0) {
			staticForwardSolver.solve();

			terminateTries = 0;
			while (terminateTries < 10) {
				if (staticExecutor.getActiveCount() != 0
						|| !staticExecutor.isTerminated()) {
					terminateTries++;
					try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						logger.error("Could not wait for executor termination",
								e);
					}
				} else
					break;
			}
			if (staticExecutor.getActiveCount() != 0
					|| !staticExecutor.isTerminated())
				logger.error("Executor did not terminate gracefully");

			staticForwardSolver.cleanup();
			staticBackSolver.cleanup();
			AccessPath.clearBaseRegister();
			Runtime.getRuntime().gc();
		} else {
			logger.info("Skipping static phase");
		}

		logger.info("Source lookup done, found {} sources and {} sinks.",
				forwardProblem.getInitialSeeds().size(), sinkCount);

		forwardProblem.setExtraSinkPoints(staticForwardProblem.getResults());
		forwardSolver.solve();

		// Not really nice, but sometimes Heros returns before all
		// executor tasks are actually done. This way, we give it a
		// chance to terminate gracefully before moving on.
		terminateTries = 0;
		while (terminateTries < 10) {
			if (executor.getActiveCount() != 0 || !executor.isTerminated()) {
				terminateTries++;
				try {
					Thread.sleep(500);
				} catch (InterruptedException e) {
					logger.error("Could not wait for executor termination", e);
				}
			} else
				break;
		}
		if (executor.getActiveCount() != 0 || !executor.isTerminated())
			logger.error("Executor did not terminate gracefully");

		// Print taint wrapper statistics
		if (taintWrapper != null) {
			logger.info("Taint wrapper hits: " + taintWrapper.getWrapperHits());
			logger.info("Taint wrapper misses: "
					+ taintWrapper.getWrapperMisses());
		}

		res = forwardProblem.getResults();

		logger.info(
				"IFDS problem with {} forward and {} backward edges solved, "
						+ "processing {} results...",
				forwardSolver.propagationCount, backSolver == null ? 0
						: backSolver.propagationCount,
				res == null ? 0 : res.size());

		// Force a cleanup. Everything we need is reachable through the
		// results set, the other abstractions can be killed now.
		forwardSolver.cleanup();
		if (backSolver != null) {
			backSolver.cleanup();
			backSolver = null;
			backProblem = null;
		}
		forwardSolver = null;
		forwardProblem = null;
		AccessPath.clearBaseRegister();
		Runtime.getRuntime().gc();

		computeTaintPaths(res);

		if (results.getResults().isEmpty())
			logger.warn("No results found.");
		else
			for (Entry<SinkInfo, Set<SourceInfo>> entry : results.getResults()
					.entrySet()) {
				logger.info(
						"The sink {} in method {} was called with values from the following sources:",
						entry.getKey(),
						iCfg.getMethodOf(entry.getKey().getContext())
								.getSignature());
				for (SourceInfo source : entry.getValue()) {
					logger.info("- {} in method {}", source,
							iCfg.getMethodOf(source.getContext())
									.getSignature());
					if (source.getPath() != null && !source.getPath().isEmpty()) {
						logger.info("\ton Path: ");
						for (Unit p : source.getPath()) {
							logger.info("\t -> " + iCfg.getMethodOf(p));
							logger.info("\t\t -> " + p);
						}
					}
				}
			}

		for (ResultsAvailableHandler handler : onResultsAvailable)
			handler.onResultsAvailable(iCfg, results);
	}

	/**
	 * Creates a new executor object for spawning worker threads
	 * 
	 * @param numThreads
	 *            The number of threads to use
	 * @return The generated executor
	 */
	private CountingThreadPoolExecutor createExecutor(int numThreads) {
		return new CountingThreadPoolExecutor(maxThreadNum == -1 ? numThreads
				: Math.min(maxThreadNum, numThreads), Integer.MAX_VALUE, 30,
				TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>());
	}

	/**
	 * Computes the path of tainted data between the source and the sink
	 * 
	 * @param res
	 *            The data flow tracker results
	 */
	private void computeTaintPaths(final Set<AbstractionAtSink> res) {
		IAbstractionPathBuilder builder = this.pathBuilderFactory
				.createPathBuilder(maxThreadNum);
		if (computeResultPaths)
			builder.computeTaintPaths(res);
		else
			builder.computeTaintSources(res);
		this.results = builder.getResults();
		builder.shutdown();
	}

	private Collection<SootMethod> getMethodsForSeeds(IInfoflowCFG icfg) {
		List<SootMethod> seeds = new LinkedList<SootMethod>();
		// If we have a callgraph, we retrieve the reachable methods. Otherwise,
		// we have no choice but take all application methods as an
		// approximation
		if (Scene.v().hasCallGraph()) {
			List<MethodOrMethodContext> eps = new ArrayList<MethodOrMethodContext>(
					Scene.v().getEntryPoints());
			ReachableMethods reachableMethods = new ReachableMethods(Scene.v()
					.getCallGraph(), eps.iterator(), null);
			reachableMethods.update();
			for (Iterator<MethodOrMethodContext> iter = reachableMethods
					.listener(); iter.hasNext();)
				seeds.add(iter.next().method());
		} else {
			long beforeSeedMethods = System.nanoTime();
			Set<SootMethod> doneSet = new HashSet<SootMethod>();
			for (SootMethod sm : Scene.v().getEntryPoints())
				getMethodsForSeedsIncremental(sm, doneSet, seeds, icfg);
			logger.info("Collecting seed methods took {} seconds",
					(System.nanoTime() - beforeSeedMethods) / 1E9);
		}
		return seeds;
	}

	private void getMethodsForSeedsIncremental(SootMethod sm,
			Set<SootMethod> doneSet, List<SootMethod> seeds, IInfoflowCFG icfg) {
		assert Scene.v().hasFastHierarchy();
		if (!sm.isConcrete() || !sm.getDeclaringClass().isApplicationClass()
				|| !doneSet.add(sm))
			return;
		seeds.add(sm);
		for (Unit u : sm.retrieveActiveBody().getUnits()) {
			Stmt stmt = (Stmt) u;
			if (stmt.containsInvokeExpr())
				for (SootMethod callee : icfg.getCalleesOfCallAt(stmt))
					getMethodsForSeedsIncremental(callee, doneSet, seeds, icfg);
		}
	}

	/**
	 * Scans the given method for sources and sinks contained in it. Sinks are
	 * just counted, sources are added to the InfoflowProblem as seeds.
	 * 
	 * @param sourcesSinks
	 *            The SourceSinkManager to be used for identifying sources and
	 *            sinks
	 * @param forwardProblem
	 *            The InfoflowProblem in which to register the sources as seeds
	 * @param m
	 *            The method to scan for sources and sinks
	 * @return The number of sinks found in this method
	 */
	private int scanMethodForSourcesSinks(
			final ISourceSinkManager sourcesSinks,
			InfoflowProblem forwardProblem,
			InfoflowProblem staticForwardProblem, SootMethod m) {
		int sinkCount = 0;
		if (m.hasActiveBody()) {
			// Check whether this is a system class we need to ignore
			final String className = m.getDeclaringClass().getName();
			if (ignoreFlowsInSystemPackages
					&& SystemClassHandler.isClassInSystemPackage(className))
				return sinkCount;

			// Look for a source in the method. Also look for sinks. If we
			// have no sink in the program, we don't need to perform any
			// analysis
			PatchingChain<Unit> units = m.getActiveBody().getUnits();
			Stmt old_s = null; // DIDFAIL

			for (Unit u : units) {
				Stmt s = (Stmt) u;

				// We were using the piece of code below to identify the all
				// instances of getIntent() being called inside onCreate()
				// But we aren't using it anymore, since we realized that we can
				// mark the Unit returned by getIntent() as Source just by
				// adding
				// the method as a Source inside the SourcesAndSinks.txt file
				if (m.getSubSignature().equals(
						"void onCreate(android.os.Bundle)")) {
					try {
						AbstractInvokeExpr ie = (AbstractInvokeExpr) s
								.getInvokeExpr();
						String subSig = ie.getMethod().getSubSignature();
						if (subSig
								.contains("android.content.Intent getIntent()")) {
							logger.info("getIntent() called inside onCreate() in class: "
									+ m.getDeclaringClass().getName());
						}
					} catch (Exception e) {
					}
				}
				// *******

				if (sourcesSinks.getSourceInfo(s, iCfg) != null) {
					if (s.hasTag("StaticSourceTag")) {
						staticForwardProblem.addInitialSeeds(u, Collections
								.singleton(staticForwardProblem.zeroValue()));
						forwardProblem.addInitialSeeds(u, Collections
								.singleton(forwardProblem.zeroValue()));
					} else {
						forwardProblem.addInitialSeeds(u, Collections
								.singleton(forwardProblem.zeroValue()));
					}
					logger.debug("Source found: {}", u);
				}
				if (sourcesSinks.isSink(s, iCfg)) {
					logger.debug("Sink found: {}", u);
					if (isIntentSink(s)) {
						String emph = "\u001B[31m";
						String ansi_reset = "\u001B[0m";
						logger.info(emph + "INTENT SINK: " + ansi_reset
								+ s.toString());
						logger.info(emph + "PREV: " + ansi_reset
								+ old_s.toString());
						String intentID = extractIntentID(old_s);
						logger.info(emph + "IntentID: " + ansi_reset + intentID);
						s.addTag(new IntentTag("IntentID", intentID));
						logger.info(emph
								+ "IntentID: "
								+ ansi_reset
								+ ((IntentTag) s.getTag("IntentID"))
										.getIntentID());
					}
					sinkCount++;
				}

				old_s = s;
			}

		}
		return sinkCount;
	}

	@Override
	public InfoflowResults getResults() {
		return results;
	}

	@Override
	public boolean isResultAvailable() {
		if (results == null) {
			return false;
		}
		return true;
	}

	public static int getAccessPathLength() {
		return accessPathLength;
	}

	/**
	 * Sets the maximum depth of the access paths. All paths will be truncated
	 * if they exceed the given size.
	 * 
	 * @param accessPathLength
	 *            the maximum value of an access path. If it gets longer than
	 *            this value, it is truncated and all following fields are
	 *            assumed as tainted (which is imprecise but gains performance)
	 *            Default value is 5.
	 */
	public static void setAccessPathLength(int accessPathLength) {
		Infoflow.accessPathLength = accessPathLength;
	}

	/**
	 * Sets whether results (source-to-sink connections) that only differ in
	 * their propagation paths shall be merged into a single result or not.
	 * 
	 * @param pathAgnosticResults
	 *            True if two results shall be regarded as equal if they connect
	 *            the same source and sink, even if their propagation paths
	 *            differ, otherwise false
	 */
	public static void setPathAgnosticResults(boolean pathAgnosticResults) {
		Infoflow.pathAgnosticResults = pathAgnosticResults;
	}

	/**
	 * Gets whether results (source-to-sink connections) that only differ in
	 * their propagation paths shall be merged into a single result or not.
	 * 
	 * @return True if two results shall be regarded as equal if they connect
	 *         the same source and sink, even if their propagation paths differ,
	 *         otherwise false
	 */
	public static boolean getPathAgnosticResults() {
		return Infoflow.pathAgnosticResults;
	}

	/**
	 * Gets whether recursive access paths shall be reduced, e.g. whether we
	 * shall propagate a.[next].data instead of a.next.next.data.
	 * 
	 * @return True if recursive access paths shall be reduced, otherwise false
	 */
	public static boolean getUseRecursiveAccessPaths() {
		return useRecursiveAccessPaths;
	}

	/**
	 * Sets whether recursive access paths shall be reduced, e.g. whether we
	 * shall propagate a.[next].data instead of a.next.next.data.
	 * 
	 * @param useRecursiveAccessPaths
	 *            True if recursive access paths shall be reduced, otherwise
	 *            false
	 */
	public static void setUseRecursiveAccessPaths(
			boolean useRecursiveAccessPaths) {
		Infoflow.useRecursiveAccessPaths = useRecursiveAccessPaths;
	}

	/**
	 * Adds a handler that is called when information flow results are available
	 * 
	 * @param handler
	 *            The handler to add
	 */
	public void addResultsAvailableHandler(ResultsAvailableHandler handler) {
		this.onResultsAvailable.add(handler);
	}

	/**
	 * Adds a handler which is invoked whenever a taint is propagated
	 * 
	 * @param handler
	 *            The handler to be invoked when propagating taints
	 */
	public void addTaintPropagationHandler(TaintPropagationHandler handler) {
		this.taintPropagationHandlers.add(handler);
	}

	/**
	 * Removes a handler that is called when information flow results are
	 * available
	 * 
	 * @param handler
	 *            The handler to remove
	 */
	public void removeResultsAvailableHandler(ResultsAvailableHandler handler) {
		onResultsAvailable.remove(handler);
	}

	@Override
	public void setIPCManager(IIPCManager ipcManager) {
		this.ipcManager = ipcManager;
	}

	// BEGIN DIDFAIL ADDITIONS

	public static boolean isIntentSink(Stmt stmt) {
		if (!stmt.containsInvokeExpr()) {
			return false;
		}
		AbstractInvokeExpr ie = (AbstractInvokeExpr) stmt.getInvokeExpr();
		SootMethod meth = ie.getMethod();
		SootClass android_content_Context = Scene.v().getSootClass(
				"android.content.Context");
		// FIXME: Check the method name better!
		if (meth.toString().indexOf("startActivity") == -1) {
			return false;
		}
		return ((new Hierarchy()).isClassSuperclassOfIncluding(
				android_content_Context, meth.getDeclaringClass()));
	}

	public static boolean isIntentResultSink(Stmt stmt) {
		if (!stmt.containsInvokeExpr()) {
			return false;
		}
		AbstractInvokeExpr ie = (AbstractInvokeExpr) stmt.getInvokeExpr();
		SootMethod meth = ie.getMethod();
		SootClass android_content_Context = Scene.v().getSootClass(
				"android.app.Activity");
		if (meth.toString().indexOf("setResult") == -1) {
			return false;
		}
		return ((new Hierarchy()).isClassSuperclassOfIncluding(
				android_content_Context, meth.getDeclaringClass()));
	}

	public static String extractIntentID(Stmt prevStmt) {
		try {
			if (!prevStmt.containsInvokeExpr()) {
				return "";
			}
			AbstractInvokeExpr ie = (AbstractInvokeExpr) prevStmt
					.getInvokeExpr();
			String sig = ie.getMethod().getSignature();
			if (!sig.equals("<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)>")) {
				return "";
			}
			StringConstant ret = (StringConstant) ie.getArg(0);
			return ret.value;
		} catch (Exception e) {
			return "";
		}
	}

	// END DIDFAIL ADDITIONS
}
