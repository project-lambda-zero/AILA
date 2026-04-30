// ExportDecompilation.java — Ghidra headless post-analysis script.
// Decompiles all functions and prints C-like pseudocode.
// Usage: analyzeHeadless <project> <name> -import <binary> -postScript ExportDecompilation.java
//
// @category AILA.Forensics
// @author AILA Forensics Module

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportDecompilation extends GhidraScript {

    @Override
    protected void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        println("=== DECOMPILATION EXPORT ===");
        while (funcs.hasNext()) {
            Function f = funcs.next();
            DecompileResults res = decomp.decompileFunction(f, 30, monitor);
            DecompiledFunction d = res.getDecompiledFunction();
            if (d != null) {
                println("--- " + f.getName() + " @ " + f.getEntryPoint() + " ---");
                println(d.getC());
            }
            count++;
            if (count >= 500) {
                println("... truncated at 500 functions ...");
                break;
            }
        }
        decomp.dispose();
        println(String.format("=== DECOMPILED: %d functions ===", count));
    }
}
