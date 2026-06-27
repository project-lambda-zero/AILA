// ListFunctions.java -- Ghidra headless post-analysis script.
// Lists all functions in the current program with address + name + size.
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript ListFunctions.java
//
// @category AILA.Forensics
// @author AILA Forensics Module

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ListFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        println("=== FUNCTION LIST ===");
        while (funcs.hasNext()) {
            Function f = funcs.next();
            String addr = f.getEntryPoint().toString();
            String name = f.getName();
            long size = f.getBody().getNumAddresses();
            println(String.format("FUNC %s %s size=%d", addr, name, size));
            count++;
        }
        println(String.format("=== TOTAL: %d functions ===", count));
    }
}
