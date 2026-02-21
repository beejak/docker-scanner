package com.dockerscanner

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.OSProcessHandler
import com.intellij.execution.process.ProcessAdapter
import com.intellij.execution.process.ProcessEvent
import com.intellij.execution.ui.ConsoleView
import com.intellij.execution.ui.ConsoleViewContentType
import com.intellij.execution.ui.RunContentDescriptor
import com.intellij.execution.ui.RunContentManager
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.execution.impl.ConsoleViewImpl
import java.io.File

class ScanImageAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val image = Messages.showInputDialog(
            project,
            "Image to scan (e.g. alpine:latest or myregistry.io/app:v1)",
            "Docker Scanner",
            Messages.getQuestionIcon(),
            "alpine:latest",
            null
        ) ?: return
        val imageTrim = image.trim()
        if (imageTrim.isEmpty()) return

        val dockerfile = Messages.showInputDialog(
            project,
            "Optional Dockerfile path (relative to project or absolute). Leave empty to skip.",
            "Docker Scanner",
            Messages.getQuestionIcon(),
            "",
            null
        )?.trim()

        val basePath = project.basePath ?: "."
        val reportsDir = File(basePath, "reports").absolutePath
        val args = mutableListOf("scan", "--image", imageTrim, "--output-dir", reportsDir, "--format", "markdown,html")
        if (!dockerfile.isNullOrEmpty()) {
            val dfPath = File(basePath, dockerfile).absolutePath
            args.add("--dockerfile")
            args.add(dfPath)
        }

        val cliPath = "scanner"
        val cmd = GeneralCommandLine(cliPath).withWorkDirectory(File(basePath)).withParameters(args)
        val handler = OSProcessHandler(cmd)
        val consoleView = ConsoleViewImpl(project, false)
        consoleView.attachToProcess(handler)

        handler.addProcessListener(object : ProcessAdapter() {
            override fun processTerminated(event: ProcessEvent) {
                if (event.exitCode == 0) {
                    consoleView.print("\nDone. Reports in $reportsDir\n", ConsoleViewContentType.NORMAL_OUTPUT)
                    Messages.showInfoMessage(project, "Scan complete. Reports in $reportsDir", "Docker Scanner")
                } else {
                    Messages.showErrorDialog(project, "Scan failed (exit code ${event.exitCode}). See Run window.", "Docker Scanner")
                }
            }
        })

        val descriptor = RunContentDescriptor(consoleView, handler, "Docker Scanner: $imageTrim")
        RunContentManager.getInstance(project).showRunContent(descriptor)
        handler.startNotify()
    }
}
