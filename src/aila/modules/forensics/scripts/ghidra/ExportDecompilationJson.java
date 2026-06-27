// ExportDecompilationJson.java -- Ghidra headless post-analysis script.
// Emits a machine-parseable JSON array of decompiled functions so the
// collector can store them as records[] without regex-splitting a text blob.
//
// Output shape (one JSON object printed between begin/end sentinels):
//   {
//     "total_functions": <int>,
//     "functions": [
//       { "address": "0x401000", "name": "main", "size": 120,
//         "callees": ["0x401500", "0x4021a0"],
//         "is_external": false, "is_thunk": false,
//         "c_source": "..." }
//     ]
//   }
//
// Usage:
//   analyzeHeadless <proj> <name> -import <binary> -overwrite -readOnly \
//     -scriptPath <dir> -postScript ExportDecompilationJson.java \
//     [max_funcs] [max_c_chars]
// Default caps: 200 functions, 8000 C chars per function.
//
// @category AILA.Forensics
// @author AILA Forensics Module

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.listing.Listing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public class ExportDecompilationJson extends GhidraScript {

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        int maxFuncs = 200;
        int maxChars = 8000;
        if (args != null) {
            if (args.length >= 1) { try { maxFuncs = Integer.parseInt(args[0]); } catch (NumberFormatException ignore) {} }
            if (args.length >= 2) { try { maxChars = Integer.parseInt(args[1]); } catch (NumberFormatException ignore) {} }
        }

        // Collect every function up-front so we can rank by size and keep
        // the most substantial ones when maxFuncs is the binding limit.
        // The iterator is a live view; we snapshot names/addresses first
        // and only pay for decompilation on the survivors.
        List<Function> all = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            all.add(it.next());
        }
        int total = all.size();

        // Rank by body size descending -- bigger functions usually carry
        // the interesting logic; thunks / stubs are tiny and skippable.
        Collections.sort(all, new Comparator<Function>() {
            @Override
            public int compare(Function a, Function b) {
                long sa = a.getBody().getNumAddresses();
                long sb = b.getBody().getNumAddresses();
                return Long.compare(sb, sa);
            }
        });

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder out = new StringBuilder(1024 * 64);
        out.append("{\"total_functions\":").append(total).append(",\"functions\":[");

        int emitted = 0;
        Listing listing = currentProgram.getListing();
        for (Function f : all) {
            if (emitted >= maxFuncs) break;
            Address entry = f.getEntryPoint();
            long bodySize = f.getBody().getNumAddresses();

            // Callees: every outbound reference from any instruction in
            // this function body whose target lies in another function.
            List<String> callees = new ArrayList<>();
            try {
                ReferenceIterator rit = currentProgram.getReferenceManager()
                        .getReferenceIterator(entry);
                int hops = 0;
                while (rit.hasNext() && hops < 64) {
                    Reference ref = rit.next();
                    if (ref.getReferenceType().isCall()) {
                        callees.add(ref.getToAddress().toString());
                    }
                    hops++;
                }
            } catch (Exception ignore) {
                // Best-effort; some programs refuse the iterator.
            }

            String cSource = "";
            try {
                DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                DecompiledFunction d = res.getDecompiledFunction();
                if (d != null) {
                    cSource = d.getC();
                    if (cSource.length() > maxChars) {
                        cSource = cSource.substring(0, maxChars) + "\n/* ...truncated... */";
                    }
                }
            } catch (Exception e) {
                cSource = "";
            }

            if (emitted > 0) out.append(",");
            out.append("{");
            out.append("\"address\":\"").append(jsonEscape(entry.toString())).append("\",");
            out.append("\"name\":\"").append(jsonEscape(f.getName())).append("\",");
            out.append("\"size\":").append(bodySize).append(",");
            out.append("\"is_thunk\":").append(f.isThunk()).append(",");
            out.append("\"is_external\":").append(f.isExternal()).append(",");
            out.append("\"callees\":[");
            for (int i = 0; i < callees.size(); i++) {
                if (i > 0) out.append(",");
                out.append("\"").append(jsonEscape(callees.get(i))).append("\"");
            }
            out.append("],");
            out.append("\"c_source\":\"").append(jsonEscape(cSource)).append("\"");
            out.append("}");
            emitted++;
        }
        out.append("]}");

        decomp.dispose();

        // Wrap the blob in sentinels so the collector can extract it
        // from headless's mixed stdout without regex acrobatics.
        println("AILA_GHIDRA_JSON_BEGIN");
        println(out.toString());
        println("AILA_GHIDRA_JSON_END");
    }
}
