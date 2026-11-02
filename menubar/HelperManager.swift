// HelperManager — côté app : enregistre le daemon root (SMAppService) et lui parle
// en XPC pour activer/désactiver sudo. Remplace l'ancien Run.admin (osascript), cassé
// sur macOS 26 (authtrampoline casse l'attribution → écriture /etc/pam.d refusée).
import Foundation
import ServiceManagement
import AppKit
import Security
import os

final class HelperManager {
    static let shared = HelperManager()
    private let plistName = "com.lorenzo.Mugshot.Helper.plist"
    private var service: SMAppService { SMAppService.daemon(plistName: plistName) }

    var isEnabled: Bool { service.status == .enabled }

    /// Chemin du binaire du daemon (à ajouter à l'Accès complet au disque sur macOS 26).
    var helperPath: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/MugshotHelper").path
    }

    /// Ouvre le volet Réglages › Confidentialité › Accès complet au disque.
    func openFullDiskAccess() {
        if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(u)
        }
    }

    enum Reg { case enabled, needsApproval, failed(String) }

    private func openApproval() {
        if Thread.isMainThread {
            SMAppService.openSystemSettingsLoginItems()
        } else {
            DispatchQueue.main.async { SMAppService.openSystemSettingsLoginItems() }
        }
    }

    /// Enregistre le daemon si nécessaire. `.needsApproval` → l'utilisateur doit
    /// l'activer dans Réglages > Éléments d'ouverture (on ouvre la fenêtre).
    func ensureRegistered() -> Reg {
        switch service.status {
        case .enabled:
            return .enabled
        case .requiresApproval:
            openApproval()
            return .needsApproval
        default:
            do {
                try service.register()
                switch service.status {
                case .enabled: return .enabled
                case .requiresApproval:
                    openApproval()
                    return .needsApproval
                default: return .failed("statut inattendu : \(service.status.rawValue)")
                }
            } catch {
                if service.status == .requiresApproval {
                    openApproval()
                    return .needsApproval
                }
                return .failed(error.localizedDescription)
            }
        }
    }

    func unregister() { try? service.unregister() }

    /// Réenregistre explicitement le daemon après remplacement d'un build local
    /// ad-hoc (son cdhash change et macOS invalide alors l'ancien enregistrement).
    func refreshRegistration() -> Reg {
        do {
            if service.status != .notRegistered {
                try service.unregister()
            }
            try service.register()
            switch service.status {
            case .enabled:
                return .enabled
            case .requiresApproval:
                openApproval()
                return .needsApproval
            default:
                return .failed("statut inattendu : \(service.status.rawValue)")
            }
        } catch {
            if service.status == .requiresApproval {
                openApproval()
                return .needsApproval
            }
            return .failed(error.localizedDescription)
        }
    }

    // MARK: XPC

    /// Construit une exigence adaptée à la signature réellement installée.
    /// - Developer ID : même Team ID que l'app.
    /// - build local ad-hoc : cdhash exact du helper embarqué.
    private func helperCodeSigningRequirement() -> String? {
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode else { return nil }
        var selfStaticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(selfCode, [], &selfStaticCode) == errSecSuccess,
              let selfStaticCode else { return nil }

        var selfInfoRef: CFDictionary?
        guard SecCodeCopySigningInformation(selfStaticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &selfInfoRef) == errSecSuccess,
              let selfInfo = selfInfoRef as? [String: Any] else { return nil }

        if let teamID = selfInfo[kSecCodeInfoTeamIdentifier as String] as? String,
           !teamID.isEmpty {
            return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        }

        var helperCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: helperPath) as CFURL, [], &helperCode) == errSecSuccess,
              let helperCode else { return nil }
        var helperInfoRef: CFDictionary?
        guard SecCodeCopySigningInformation(helperCode, SecCSFlags(rawValue: kSecCSSigningInformation), &helperInfoRef) == errSecSuccess,
              let helperInfo = helperInfoRef as? [String: Any],
              let cdhash = helperInfo[kSecCodeInfoUnique as String] as? Data else { return nil }
        return "cdhash H\"\(cdhash.map { String(format: "%02x", $0) }.joined())\""
    }

    private func newConnection(exporting events: MugshotKeyEventsProtocol? = nil) -> NSXPCConnection {
        let c = NSXPCConnection(machServiceName: kMugshotHelperMachService, options: .privileged)
        c.remoteObjectInterface = NSXPCInterface(with: MugshotHelperProtocol.self)
        if let events {
            c.exportedInterface = NSXPCInterface(with: MugshotKeyEventsProtocol.self)
            c.exportedObject = events
        }
        if let requirement = helperCodeSigningRequirement() {
            c.setCodeSigningRequirement(requirement)
        } else {
            NSLog("Mugshot: impossible de construire l'exigence de signature du helper; validation côté helper uniquement")
        }
        c.resume()
        return c
    }

    private func call(_ invoke: @escaping (MugshotHelperProtocol, @escaping (Bool, String) -> Void) -> Void,
                      _ done: @escaping (Bool, String) -> Void) {
        let c = newConnection()
        let proxy = c.remoteObjectProxyWithErrorHandler { err in
            DispatchQueue.main.async { done(false, "Connexion au helper : \(err.localizedDescription)") }
        } as? MugshotHelperProtocol
        guard let proxy else { done(false, "Proxy XPC indisponible."); return }
        invoke(proxy) { ok, msg in
            DispatchQueue.main.async { c.invalidate(); done(ok, msg) }
        }
    }

    /// Active sudo via le daemon root. `done` appelé sur le main thread.
    func enableSudo(_ done: @escaping (Bool, String) -> Void) {
        call({ $0.enableSudo(withReply: $1) }, done)
    }
    func disableSudo(_ done: @escaping (Bool, String) -> Void) {
        call({ $0.disableSudo(withReply: $1) }, done)
    }

    /// Le helper a-t-il le droit d'écrire dans /etc/pam.d ? Ne modifie rien.
    func checkAccess(_ done: @escaping (Bool, String) -> Void) {
        call({ $0.checkAccess(withReply: $1) }, done)
    }

    // MARK: lock-screen key watch

    private final class KeyEvents: NSObject, MugshotKeyEventsProtocol {
        let handler: (Bool) -> Void
        init(_ handler: @escaping (Bool) -> Void) { self.handler = handler }
        func keyDecision(isTrigger: Bool) { DispatchQueue.main.async { self.handler(isTrigger) } }
    }
    private var watchConnection: NSXPCConnection?

    private static let trace = Logger(subsystem: "com.lorenzo.Mugshot", category: "helper")
    private static let approvalAskedKey = "faceid.helperApprovalAsked"

    /// Registers the daemon at launch. The approval pane opens at most once, so a user who ignores
    /// it is not nagged on every launch; the status is logged either way.
    func registerQuietly() {
        Self.trace.notice("helper status at launch: \(self.service.status.rawValue)")
        guard service.status != .enabled else { return }
        var registration = "ok"
        if service.status != .requiresApproval {
            do { try service.register() } catch { registration = error.localizedDescription }
        }
        Self.trace.notice("helper register: \(registration, privacy: .public); status=\(self.service.status.rawValue)")
        let defaults = UserDefaults.standard
        if service.status == .requiresApproval, !defaults.bool(forKey: Self.approvalAskedKey) {
            defaults.set(true, forKey: Self.approvalAskedKey)
            openApproval()
        }
    }

    /// Asks the root daemon to read the keyboards while the screen is locked. The connection stays
    /// open for the whole lock: closing it (or the app quitting) stops the daemon's watch.
    /// `decision` runs on the main thread: true for the trigger key, false for any other key.
    func startKeyWatch(trigger: Int, decision: @escaping (Bool) -> Void, done: @escaping (Bool, String) -> Void) {
        stopKeyWatch()
        guard isEnabled else { done(false, "helper not enabled (status \(service.status.rawValue))"); return }
        let c = newConnection(exporting: KeyEvents(decision))
        watchConnection = c
        let proxy = c.remoteObjectProxyWithErrorHandler { err in
            DispatchQueue.main.async { done(false, "helper connection: \(err.localizedDescription)") }
        } as? MugshotHelperProtocol
        guard let proxy else { done(false, "XPC proxy unavailable"); return }
        proxy.startKeyWatch(trigger: trigger) { ok, message in DispatchQueue.main.async { done(ok, message) } }
    }

    func stopKeyWatch() {
        watchConnection?.invalidate()
        watchConnection = nil
    }

    /// Exécute une opération privilégiée en s'assurant d'abord que le helper existe.
    ///
    /// Installé par le paquet, `sudo` est branché par l'Installeur lui-même : aucun
    /// helper n'a jamais été enregistré. Tout appel XPC partait alors vers un service
    /// inexistant et échouait — le bouton « Désactiver » comme la désinstallation
    /// semblaient ne rien faire. Passer par ici garantit qu'on l'enregistre au besoin,
    /// et que l'appelant reçoit un motif exploitable au lieu d'une erreur de connexion.
    func withHelper(_ action: @escaping (@escaping (Bool, String) -> Void) -> Void,
                    _ done: @escaping (Bool, String) -> Void) {
        guard !isEnabled else { action(done); return }
        switch ensureRegistered() {
        case .enabled:
            action(done)
        case .needsApproval:
            done(false, L("uninstall.needs.helper"))
        case .failed(let message):
            done(false, message)
        }
    }

    /// Teste uniquement le canal XPC; ne modifie pas la configuration PAM.
    func probe(_ done: @escaping (Bool, String) -> Void) {
        let c = newConnection()
        let proxy = c.remoteObjectProxyWithErrorHandler { err in
            DispatchQueue.main.async {
                c.invalidate()
                done(false, "Connexion au helper : \(err.localizedDescription)")
            }
        } as? MugshotHelperProtocol
        guard let proxy else {
            c.invalidate()
            done(false, "Proxy XPC indisponible.")
            return
        }
        proxy.version { version in
            DispatchQueue.main.async {
                c.invalidate()
                done(version == kMugshotHelperVersion,
                     version == kMugshotHelperVersion
                        ? "helper v\(version) joignable"
                        : "version helper incompatible : \(version)")
            }
        }
    }
}
