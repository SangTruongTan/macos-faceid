// MugshotHelper — daemon root (LaunchDaemon via SMAppService). Reçoit en XPC les
// ordres enable/disable sudo et exécute les scripts privilégiés en root, avec une
// vraie attribution système (pas d'authtrampoline) → l'écriture /etc/pam.d passe.
// N'accepte QUE les connexions d'un client signé comme nous (CodesignCheck).
import Foundation

/// Chemin de l'exécutable du helper, fiable même lancé par launchd.
func helperExecutablePath() -> String {
    var size: UInt32 = 0
    _NSGetExecutablePath(nil, &size)
    var buf = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buf, &size) == 0 else { return CommandLine.arguments[0] }
    return String(cString: buf)
}

/// <App>.app/Contents/Resources déduit depuis .../Contents/MacOS/MugshotHelper.
func resourcesDir() -> URL {
    URL(fileURLWithPath: helperExecutablePath())
        .resolvingSymlinksInPath()
        .deletingLastPathComponent()   // Contents/MacOS
        .deletingLastPathComponent()   // Contents
        .appendingPathComponent("Resources")
}

final class HelperDelegate: NSObject, NSXPCListenerDelegate, MugshotHelperProtocol {
    // Auto-arrêt après inactivité : un process root ne doit pas traîner, ET ça permet
    // qu'un nouvel octroi TCC (Accès complet au disque) soit pris en compte au relancement.
    private let idleQueue = DispatchQueue(label: "com.lorenzo.Mugshot.Helper.idle")
    private var idleWork: DispatchWorkItem?
    private func resetIdle() {
        idleQueue.async {
            self.idleWork?.cancel()
            // Jamais d'arrêt pendant une surveillance du clavier.
            let w = DispatchWorkItem { DispatchQueue.main.async { if self.watcher == nil { exit(0) } } }
            self.idleWork = w
            self.idleQueue.asyncAfter(deadline: .now() + 20, execute: w)
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        guard (try? CodesignCheck.codeSigningMatches(pid: c.processIdentifier)) == true else {
            NSLog("MugshotHelper: connexion refusée (signature client invalide)")
            return false
        }
        c.exportedInterface = NSXPCInterface(with: MugshotHelperProtocol.self)
        c.exportedObject = self
        c.remoteObjectInterface = NSXPCInterface(with: MugshotKeyEventsProtocol.self)
        let end = { [weak self] in DispatchQueue.main.async { self?.endWatch(for: c) } }
        c.invalidationHandler = end
        c.interruptionHandler = end
        c.resume()
        resetIdle()
        return true
    }

    private func runScript(_ name: String, reply: @escaping (Bool, String) -> Void) {
        let script = resourcesDir().appendingPathComponent("scripts/\(name)").path
        guard FileManager.default.fileExists(atPath: script) else {
            reply(false, "script introuvable : \(script)"); return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [script]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        do { try p.run() } catch { reply(false, "\(error)"); return }
        p.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        reply(p.terminationStatus == 0, out.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    func enableSudo(withReply reply: @escaping (Bool, String) -> Void) {
        runScript("pam-install-root.sh", reply: reply)
    }
    func disableSudo(withReply reply: @escaping (Bool, String) -> Void) {
        runScript("pam-uninstall-root.sh", reply: reply)
    }
    // MARK: surveillance du clavier (écran verrouillé)
    // Toujours sur le thread principal : les périphériques HID y sont planifiés.
    private var watcher: KeyWatcher?
    private var watchConnection: NSXPCConnection?
    private var watchTimeout: DispatchWorkItem?
    // Plus long que le délai d'armement maximal de l'app (2 h).
    private static let watchLimit: TimeInterval = 7500

    func startKeyWatch(trigger: Int, withReply reply: @escaping (Bool, String) -> Void) {
        guard let connection = NSXPCConnection.current() else { reply(false, "no connection"); return }
        DispatchQueue.main.async {
            self.endWatch(for: nil)
            let events = connection.remoteObjectProxy as? MugshotKeyEventsProtocol
            let watcher = KeyWatcher(triggerUsage: UInt32(truncatingIfNeeded: trigger)) { decision in
                events?.keyDecision(isTrigger: decision == .trigger)
            }
            watcher.start()
            self.watcher = watcher
            self.watchConnection = connection
            let timeout = DispatchWorkItem { [weak self] in self?.endWatch(for: nil) }
            self.watchTimeout = timeout
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.watchLimit, execute: timeout)
            // Devices attach asynchronously; report once they had time to open.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                reply(true, "input monitoring=\(watcher.listenAccess) keyboards opened=\(watcher.openedDevices) refused=\(watcher.failedOpens)")
            }
        }
    }

    func stopKeyWatch(withReply reply: @escaping (Bool, String) -> Void) {
        DispatchQueue.main.async {
            let events = self.watcher?.rawEvents ?? 0
            self.endWatch(for: nil)
            reply(true, "raw events=\(events)")
        }
    }

    /// `connection` nil : arrêt inconditionnel ; sinon seulement si c'est elle qui surveille.
    private func endWatch(for connection: NSXPCConnection?) {
        if let connection, connection !== watchConnection { return }
        watcher?.stop()
        watcher = nil
        watchConnection = nil
        watchTimeout?.cancel()
        watchTimeout = nil
        resetIdle()
    }

    func version(withReply reply: @escaping (String) -> Void) {
        reply(kMugshotHelperVersion)
    }

    /// Crée puis efface aussitôt un fichier témoin dans /etc/pam.d. C'est la seule
    /// façon fiable de savoir si l'Accès complet au disque est accordé : TCC ne
    /// répond qu'au moment de l'écriture. Le témoin est un fichier caché qu'aucune
    /// règle PAM n'inclut, donc inerte même s'il survivait à un arrêt brutal.
    func checkAccess(withReply reply: @escaping (Bool, String) -> Void) {
        let probe = "/etc/pam.d/.mugshot-access-probe"
        let fd = open(probe, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        if fd >= 0 {
            close(fd)
            unlink(probe)
            reply(true, "write access to /etc/pam.d granted")
            return
        }
        // EEXIST : un témoin traîne d'une exécution précédente — donc on avait le
        // droit d'écrire. On le nettoie et on considère l'accès acquis.
        if errno == EEXIST {
            unlink(probe)
            reply(true, "write access to /etc/pam.d granted")
            return
        }
        reply(false, "cannot write to /etc/pam.d: \(String(cString: strerror(errno)))")
    }
}

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: kMugshotHelperMachService)
listener.delegate = delegate
listener.resume()
RunLoop.main.run()
