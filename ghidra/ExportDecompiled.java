// Ghidra headless post-script: export C-like decompiler output for each function.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecompiled extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String destination = getScriptArgs().length > 0 ? getScriptArgs()[0] : ".";
        File directory = new File(destination);
        if (!directory.exists() && !directory.mkdirs())
            throw new RuntimeException("Cannot create output directory: " + directory);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        File output = new File(directory, currentProgram.getName() + ".decompiled.c");
        int exported = 0;
        try (PrintWriter writer = new PrintWriter(new FileWriter(output))) {
            writer.println("/* XRay Ghidra export. Decompiled pseudocode is approximate. */");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                writer.println("\n/* Function: " + function.getName() + " @ " + function.getEntryPoint() + " */");
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    writer.println(result.getDecompiledFunction().getC());
                    exported++;
                } else writer.println("/* Decompilation unavailable for this function. */");
            }
        } finally { decompiler.dispose(); }
        println("XRay exported " + exported + " functions to " + output.getAbsolutePath());
    }
}
