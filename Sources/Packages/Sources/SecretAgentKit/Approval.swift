@unsafe @preconcurrency import LocalAuthentication
import SecretKit

/// A pending decision on whether to approve an individual signing request.
@MainActor public final class Approval {

    /// The request awaiting approval.
    public let request: SignatureRequest
    private let context: any AuthenticationContextProtocol
    private var continuation: CheckedContinuation<(any AuthenticationContextProtocol)?, Never>?

    /// Initializes an Approval.
    /// - Parameters:
    ///   - request: The request awaiting approval.
    ///   - context: The context to approve the request with.
    init(request: SignatureRequest, context: any AuthenticationContextProtocol) {
        self.request = request
        self.context = context
    }

    /// The LAContext to embed for biometric authentication, if biometrics are available.
    public var laContext: LAContext? {
        guard let laContext = context.laContext, unsafe laContext.canEvaluatePolicy(policy, error: nil) else { return nil }
        return laContext
    }

    /// Evaluates biometric authentication, approving the request if it succeeds.
    public func authenticate() async {
        guard let laContext else { return }
        if (try? await laContext.evaluatePolicy(policy, localizedReason: laContext.localizedReason)) == true {
            finish(with: context)
        }
    }

    private var policy: LAPolicy {
        request.secret.authenticationRequirement == .biometryCurrent ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthenticationWithBiometricsOrCompanion
    }

    /// Cancels biometric authentication and evaluates password authentication instead, approving the request if it succeeds.
    public func authenticateWithPassword() async {
        await context.cancel()
        let passwordContext = AuthenticationContext(secret: request.secret, requests: [request])
        let authenticated = (try? await passwordContext.evaluate(requireBiometrics: false)) ?? false
        finish(with: authenticated ? passwordContext : nil)
    }

    /// Denies the request.
    public func deny() {
        guard continuation != nil else { return }
        context.laContext?.invalidate()
        finish(with: nil)
    }

    /// Waits for the request to be approved or denied.
    /// - Returns: The authenticated context if the request was approved, or nil if it was denied.
    func decision() async -> (any AuthenticationContextProtocol)? {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(returning: nil)
                } else {
                    self.continuation = continuation
                }
            }
        } onCancel: {
            Task { @MainActor in
                self.deny()
            }
        }
    }

    private func finish(with context: (any AuthenticationContextProtocol)?) {
        continuation?.resume(returning: context)
        continuation = nil
    }

}
