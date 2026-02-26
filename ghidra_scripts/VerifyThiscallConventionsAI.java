// Verify __thiscall calling conventions for all functions using AI AI
//@author Ben Ethington
//@category Diablo 2
//@keybinding
//@menupath Tools.MCP.Verify Thiscall Conventions
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.sourcemap.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class VerifyThiscallConventionsAI extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            popup("No program is open. Please open a program first.");
            return;
        }

        // Find the ai command
        String aiCmd = findAICommand();
        if (aiCmd == null) {
            popup("Could not find ai command. Please ensure ai CLI is installed.");
            return;
        }

        // Get all functions with __thiscall convention
        List<Function> thiscallFunctions = new ArrayList<>();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);
        
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            String callingConvention = func.getCallingConventionName();
            if (callingConvention != null && callingConvention.equals("__thiscall")) {
                thiscallFunctions.add(func);
            }
        }

        if (thiscallFunctions.isEmpty()) {
            popup("No functions found with __thiscall calling convention.");
            return;
        }

        printf("Found %d functions with __thiscall calling convention\n", thiscallFunctions.size());
        
        // Ask user if they want to proceed
        if (!askYesNo("Verify Thiscall Conventions", 
                String.format("Found %d functions with __thiscall. Process them with AI?", 
                thiscallFunctions.size()))) {
            return;
        }

        // Process each function
        monitor.initialize(thiscallFunctions.size());
        monitor.setMessage("Verifying calling conventions with AI...");
        
        int processed = 0;
        int verified = 0;
        int failed = 0;
        
        for (Function func : thiscallFunctions) {
            if (monitor.isCancelled()) {
                printf("Cancelled by user after processing %d functions\n", processed);
                break;
            }
            
            monitor.setProgress(processed);
            monitor.setMessage(String.format("Processing %s...", func.getName()));
            
            try {
                // Navigate to the function and select it
                goTo(func.getEntryPoint());
                
                // Build detailed prompt with function context
                StringBuilder promptBuilder = new StringBuilder();
                promptBuilder.append("Analyze the function '").append(func.getName())
                    .append(" and verify that the calling convention is correct for it. If the calling convention is not correct please change it to the correct calling invention.");

                String prompt = promptBuilder.toString();
                String result = callAI(aiCmd, prompt);
                
                if (result != null && !result.isEmpty()) {
                    printf("\n========================================\n");
                    printf("Function: %s @ %s\n", func.getName(), func.getEntryPoint());
                    printf("Current Convention: %s\n", func.getCallingConventionName());
                    printf("Signature: %s\n", func.getSignature().getPrototypeString());
                    printf("\nAI Analysis:\n%s\n", result);
                    printf("========================================\n");
                    verified++;
                } else {
                    printf("WARNING: No response from AI for function %s\n", func.getName());
                    failed++;
                }
                
                processed++;
                
                // Small delay to avoid overwhelming the API
                Thread.sleep(2000);
                
            } catch (Exception e) {
                printf("ERROR processing function %s: %s\n", func.getName(), e.getMessage());
                failed++;
            }
        }
        
        printf("\n========================================\n");
        printf("SUMMARY:\n");
        printf("Total functions: %d\n", thiscallFunctions.size());
        printf("Processed: %d\n", processed);
        printf("Verified: %d\n", verified);
        printf("Failed: %d\n", failed);
        printf("========================================\n");
        
        popup(String.format("Verification complete!\nProcessed: %d\nVerified: %d\nFailed: %d", 
            processed, verified, failed));
    }

    /**
     * Find the ai command based on the operating system
     */
    private String findAICommand() {
        String os = System.getProperty("os.name").toLowerCase();
        
        if (os.contains("win")) {
            // Windows: Try npm global installation path
            String appData = System.getenv("APPDATA");
            if (appData != null) {
                File aiCmd = new File(appData + "\\npm\\ai.cmd");
                if (aiCmd.exists()) {
                    return aiCmd.getAbsolutePath();
                }
            }
            
            // Try ProgramFiles
            String programFiles = System.getenv("ProgramFiles");
            if (programFiles != null) {
                File aiCmd = new File(programFiles + "\\nodejs\\ai.cmd");
                if (aiCmd.exists()) {
                    return aiCmd.getAbsolutePath();
                }
            }
        } else {
            // Unix-like systems
            String[] paths = {
                "/usr/local/bin/ai",
                "/usr/bin/ai",
                System.getProperty("user.home") + "/.local/bin/ai"
            };
            
            for (String path : paths) {
                File aiCmd = new File(path);
                if (aiCmd.exists() && aiCmd.canExecute()) {
                    return path;
                }
            }
        }
        
        return null;
    }

    /**
     * Call AI CLI with the given prompt
     */
    private String callAI(String aiCmd, String prompt) {
        StringBuilder output = new StringBuilder();
        
        try {
            // Create command: ai --dangerously-skip-permissions (read from stdin)
            List<String> command = new ArrayList<>();
            command.add(aiCmd);
            command.add("--dangerously-skip-permissions");
            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // Write prompt to stdin
            try (BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(process.getOutputStream()))) {
                writer.write(prompt);
                writer.flush();
            }
            
            // Read output
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                printf("WARNING: AI process exited with code %d\n", exitCode);
            }
            
        } catch (IOException | InterruptedException e) {
            printf("ERROR calling AI: %s\n", e.getMessage());
            return null;
        }
        
        return output.toString().trim();
    }
}
