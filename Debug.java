package soot.jimple.infoflow;

public class Debug {
	enum DebugLevel {
		None(0), Error(5), Warning(10), Info(20), All(30);

		private int level;

		private DebugLevel(int lvl) {
			this.level = lvl;
		}

		public int getLevel() {
			return this.level;
		}
	}

	public static DebugLevel DEBUG_LEVEL = DebugLevel.None;

	private Debug() {
	}

	public static void debug(DebugLevel lvl, String s) {
		if (DEBUG_LEVEL.getLevel() >= lvl.getLevel()) {
			System.out.println(s);
		}
	}

	public static void debugInfo(String s) {
		debug(DebugLevel.Info, s);
	}

	public static void debugWarning(String s) {
		debug(DebugLevel.Warning, s);
	}

	public static void debugError(String s) {
		debug(DebugLevel.Error, s);
	}
}
