// DecompileFunction.java — Ghidra headless post-analysis script.
// Decompiles a single function by name (passed as script argument).
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript DecompileFunction.java <funcName>
//
// @category AILA.Forensics
// @author AILA Forensics Module

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileFunction extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: DecompileFunction.java <function_name>");
            return;
        }
        String targetName = args[0];

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        boolean found = false;
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.getName().equals(targetName)) {
                DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                if (res.getDecompiledFunction() != null) {
                    println("--- " + f.getName() + " @ " + f.getEntryPoint() + " ---");
                    println(res.getDecompiledFunction().getC());
                } else {
                    println("Decompilation failed for " + targetName);
                }
                found = true;
                break;
            }
        }

        if (!found) {
            println("Function '" + targetName + "' not found.");
            FunctionIterator all = currentProgram.getFunctionManager().getFunctions(true);
            println("Available functions (first 50):");
            int i = 0;
            while (all.hasNext() && i < 50) {
                println("  " + all.next().getName());
                i++;
            }
        }
        decomp.dispose();
    }
}
