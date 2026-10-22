import SwiftUI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SecretKit
import SecretAgentKit
import Common

struct ApprovalView: View {

    private let authenticationHandler: any AuthenticationHandlerProtocol
    @Environment(\.dismissWindow) var dismiss
    @State private var usingPassword = false

    init(authenticationHandler: some AuthenticationHandlerProtocol) {
        self.authenticationHandler = authenticationHandler
    }

    var body: some View {
        if let approval = authenticationHandler.approval {
            VStack(spacing: 20) {
                MultilineInfoView {
                    HStack {
                        RequestHeaderView(request: approval.request)
                        Spacer()
                        if let laContext = approval.laContext {
                            TouchIDView(laContext: laContext)
                                .frame(width: 40, height: 40)
                                .task {
                                    await approval.authenticate()
                                }
                        }
                    }
                } items: {
                    if let command = approval.request.provenance.command {
                        ProcessRow(process: command, systemImage: "terminal")
                        if let directory = command.displayWorkingDirectory {
                            Label(directory, systemImage: "folder")
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        if let connected = approval.request.provenance.chain.first, connected != command {
                            ProcessRow(process: connected, systemImage: "arrow.turn.down.right")
                        }
                    }
                }
                HStack {
                    if approval.request.secret.authenticationRequirement != .biometryCurrent {
                        Button {
                            usingPassword = true
                            dismiss()
                            Task {
                                await approval.authenticateWithPassword()
                            }
                        } label: {
                            Text(.approvalUsePasswordButton)
                                .frame(maxWidth: .infinity)
                        }
                        .normalButton()
                    }
                    Button {
                        approval.deny()
                    } label: {
                        Text(.authContextRequestDenyButton)
                            .frame(maxWidth: .infinity)
                    }
                    .keyboardShortcut(.cancelAction)
                    .normalButton()
                }
                .controlSize(.large)
                .buttonBorderShape(.capsule)
            }
            .padding(20)
            .frame(width: 440)
            .onDisappear {
                if !usingPassword {
                    approval.deny()
                }
                dismiss()
            }
        }
    }

}

private struct ProcessRow: View {

    let process: SigningRequestProvenance.Process
    let systemImage: String
    @State private var expanded = false
    @State private var height: CGFloat = 0
    @State private var fullHeight: CGFloat = 0
    @State private var explaining = false

    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: systemImage)
            VStack(alignment: .leading) {
                if expanded {
                    ScrollView {
                        commandLine
                    }
                    .frame(height: min(fullHeight, 160))
                } else {
                    commandLine
                        .lineLimit(4)
                        .onGeometryChange(for: CGFloat.self, of: \.size.height) { height = $0 }
                        .background(alignment: .top) {
                            commandLine
                                .hidden()
                                .onGeometryChange(for: CGFloat.self, of: \.size.height) { fullHeight = $0 }
                        }
                }
                if expanded || fullHeight > height {
                    Button(expanded ? .approvalShowLessButton : .approvalShowMoreButton) {
                        expanded.toggle()
                    }
                    .buttonStyle(.link)
                }
            }
            Button {
                explaining = true
            } label: {
                Image(systemName: process.protected ? "lock.shield" : "exclamationmark.triangle.fill")
                    .foregroundStyle(process.protected ? Color.secondary : Color.orange)
            }
            .buttonStyle(.plain)
            .help(Text(explanation))
            .popover(isPresented: $explaining) {
                Text(explanation)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding()
                    .frame(width: 260)
            }
        }
    }

    private var explanation: LocalizedStringResource {
        process.protected ? .approvalProtectedHelp : .approvalUnprotectedHelp
    }

    private var commandLine: some View {
        Text(process.commandLine ?? process.processName)
            .monospaced()
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

}

private struct TouchIDView: NSViewRepresentable {

    let laContext: LAContext

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.sublayerTransform = CATransform3DMakeScale(40 / 64, 40 / 64, 1)
        let authenticationView = LAAuthenticationView(context: laContext)
        authenticationView.frame = NSRect(x: 0, y: 0, width: 64, height: 64)
        view.addSubview(authenticationView)
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
    }

}
