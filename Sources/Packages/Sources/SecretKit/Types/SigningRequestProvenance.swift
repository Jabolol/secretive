import Foundation
import AppKit

/// Describes the chain of applications that requested a signature operation.
public struct SigningRequestProvenance: Hashable, Sendable {

    /// A list of processes involved in the request.
    /// - Note: A chain will typically consist of many elements even for a simple request. For example, running `git fetch` in Terminal.app would generate a request chain of `ssh` -> `git` -> `zsh` -> `login` -> `Terminal.app`
    public var chain: [Process]

    public var date: Date

    public init(root: Process, date: Date = .now) {
        self.chain = [root]
        self.date = date
    }

    public var batchID: Int {
        var hasher = Hasher()
        chain.map(\.path).hash(into: &hasher)
        return hasher.finalize()
    }

}

extension SigningRequestProvenance {

    /// The `Process` which initiated the signing request.
    public var origin: Process {
        chain.last!
    }

    /// The `Process` running the command that made the request, skipping over any shell that launched it.
    /// - Note: Job control shells start each command in a new process group, so a connected process in a different process group from its parent was launched by a shell.
    public var command: Process? {
        guard chain.count > 1 else { return nil }
        let (connected, parent) = (chain[0], chain[1])
        return parent == origin || parent.processGroupID != connected.processGroupID ? connected : parent
    }

    /// A boolean describing whether all processes in the request chain had a valid code signature.
    public var intact: Bool {
        chain.allSatisfy { $0.validSignature }
    }

}

extension SigningRequestProvenance {

    /// Describes a process in a `SigningRequestProvenance` chain.
    public struct Process: Hashable, Sendable {

        /// The pid of the process.
        public let pid: Int32
        /// A user-facing name for the process.
        public let processName: String
        /// A user-facing name for the application, if one exists.
        public let appName: String?
        /// An icon representation of the application, if one exists.
        public let iconURL: URL?
        /// The path the process exists at.
        public let path: String
        /// A boolean describing whether or not the process has a valid code signature.
        public let validSignature: Bool
        /// The pid of the process's parent.
        public let parentPID: Int32?
        /// The process group ID of the process.
        public let processGroupID: Int32
        /// The arguments the process was launched with, if they could be read.
        public let arguments: [String]?
        /// The process's current working directory, if it could be read.
        public let workingDirectory: String?
        /// A boolean describing whether or not other processes are prevented from modifying the process while it runs.
        public let protected: Bool

        /// Initializes a Process.
        /// - Parameters:
        ///   - pid: The pid of the process.
        ///   - processName: A user-facing name for the process.
        ///   - appName: A user-facing name for the application, if one exists.
        ///   - iconURL: An icon representation of the application, if one exists.
        ///   - path: The path the process exists at.
        ///   - validSignature: A boolean describing whether or not the process has a valid code signature.
        ///   - parentPID: The pid of the process's parent.
        ///   - processGroupID: The process group ID of the process.
        ///   - arguments: The arguments the process was launched with, if they could be read.
        ///   - workingDirectory: The process's current working directory, if it could be read.
        ///   - protected: A boolean describing whether or not other processes are prevented from modifying the process while it runs.
        public init(pid: Int32, processName: String, appName: String?, iconURL: URL?, path: String, validSignature: Bool, parentPID: Int32?, processGroupID: Int32, arguments: [String]?, workingDirectory: String?, protected: Bool) {
            self.pid = pid
            self.processName = processName
            self.appName = appName
            self.iconURL = iconURL
            self.path = path
            self.validSignature = validSignature
            self.parentPID = parentPID
            self.processGroupID = processGroupID
            self.arguments = arguments
            self.workingDirectory = workingDirectory
            self.protected = protected
        }

        /// The best user-facing name to display for the process.
        public var displayName: String {
            appName ?? processName
        }

        /// A user-facing, shell-quoted representation of the process's command line, if its arguments could be read.
        public var commandLine: String? {
            arguments.map { ([URL(fileURLWithPath: path).lastPathComponent] + $0.dropFirst()).map(\.shellQuoted).joined(separator: " ") }
        }

        /// A user-facing representation of the process's working directory, if it could be read.
        public var displayWorkingDirectory: String? {
            workingDirectory?.displayable
        }

    }

}

private extension String {

    var displayable: String {
        let hidden: [Unicode.GeneralCategory] = [.control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned]
        return String(String.UnicodeScalarView(unicodeScalars.map { hidden.contains($0.properties.generalCategory) ? "\u{FFFD}" : $0 }))
    }

    var shellQuoted: String {
        let argument = displayable
        guard argument.isEmpty || argument.contains(where: { !$0.isLetter && !$0.isNumber && !"@%+=:,./-_~".contains($0) }) else { return argument }
        guard argument.contains("'") else { return "'" + argument + "'" }
        return "\"" + argument.replacing(/["\\$`]/) { "\\" + $0.output } + "\""
    }

}
