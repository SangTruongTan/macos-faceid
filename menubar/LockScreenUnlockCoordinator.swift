// Déverrouillage de session à la manière de Sapphire : Mugshot reconnaît le visage
// dans la session utilisateur, puis saisit le mot de passe dans loginwindow au moyen
// d'événements clavier HID. Ce n'est pas une intégration au Face ID système.
import AppKit
import ApplicationServices
import Foundation
import IOKit.hid
import os
import Security
import Darwin

@_silgen_name("CGSessionCopyCurrentDictionary")
private func CGSessionCopyCurrentDictionary() -> CFDictionary?

enum LockScreenDestination {
    static func sessionIsEligible(_ values: [String: Any], userID: uid_t = getuid()) -> Bool {
        values["CGSSessionScreenIsLocked"] as? Bool == true
            && values[kCGSessionOnConsoleKey as String] as? Bool == true
            && values[kCGSessionLoginDoneKey as String] as? Bool == true
            && (values[kCGSessionUserIDKey as String] as? NSNumber)?.uint32Value == userID
    }

    static var sessionIsEligible: Bool {
        guard let values = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return sessionIsEligible(values)
    }

    static func current() -> pid_t? {
        guard sessionIsEligible else { return nil }
        let candidates = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.loginwindow")
            .filter { !$0.isTerminated && $0.executableURL?.path == "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow" }
        guard candidates.count == 1, let application = candidates.first else { return nil }
        var code: SecCode?
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple and identifier \"com.apple.loginwindow\"" as CFString,
                                             [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: application.processIdentifier] as CFDictionary,
                                            [], &code) == errSecSuccess,
              let code,
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { return nil }
        return application.processIdentifier
    }
}

/// Re-check after Keychain retrieval: consent, session or target may have changed
/// while the secret was being read. The sender receives an explicit process ID.
enum LockScreenPasswordDelivery {
    @discardableResult
    static func deliver(load: () -> Data?, target: () -> pid_t?, post: (Data, pid_t) -> Void) -> Bool {
        guard let destination = target(), var data = load() else { return false }
        defer { data.resetBytes(in: 0..<data.count) }
        guard target() == destination else { return false }
        post(data, destination)
        return true
    }
}

enum LockScreenAccessibility {
    private static var didRequest = false
    // macOS can report AX=true while PostEvent=false for a valid Accessibility
    // grant. Either positive authorization is sufficient; two negatives block.
    static var isTrusted: Bool { AXIsProcessTrusted() || CGPreflightPostEventAccess() }

    @discardableResult
    static func request() -> Bool {
        if isTrusted { return true }
        // A rejected/stale TCC entry must not cause a fresh system alert on every
        // Configure click. Polling uses preflight only; one request per process.
        guard !didRequest else { return false }
        didRequest = true
        return CGRequestPostEventAccess()
    }

    static func openSettings() {
        guard let url = URL(string:
            "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
        else { return }
        NSWorkspace.shared.open(url)
    }

    static var diagnostic: String {
        "Accessibility AX=\(AXIsProcessTrusted()); keyboard posting=\(CGPreflightPostEventAccess()); accepted=\(isTrusted); app=\(Bundle.main.bundleURL.path)"
    }
}

final class LockScreenUnlockCoordinator {
    // Decisions only, never key contents: log show --predicate 'subsystem == "com.lorenzo.Mugshot"'
    private static let trace = Logger(subsystem: "com.lorenzo.Mugshot", category: "unlock")
    private var generation: UInt64 = 0
    private var isLocked = false
    private var isAttempting = false
    private var keyWatcher: KeyWatcher?
    // One chance per lock session: any other key, or a used attempt, disarms until the next lock.
    private var isArmed = false
    static let triggerKeyDefaultsKey = "lockUnlockKeyUsage"
    static let armTimeoutDefaultsKey = "lockArmTimeout"
    static let defaultTriggerUsage = 0x2A   // Backspace
    static let defaultArmTimeout = 300.0
    // HID keyboard usages offered in Settings; the trigger stays private to the user.
    static let triggerKeys: [(usage: Int, name: String)] = [
        (0x2A, "Backspace"), (0x4C, "Forward Delete"), (0x29, "Escape"), (0x2B, "Tab"),
        (0x35, "` (Backtick)"), (0x4A, "Home"), (0x4D, "End"), (0x4B, "Page Up"), (0x4E, "Page Down"),
        (0x68, "F13"), (0x69, "F14"), (0x6A, "F15"), (0x6B, "F16"),
    ]
    static let armTimeoutRange: ClosedRange<Double> = 60...7200

    private static var triggerUsage: UInt32 {
        let defaults = UserDefaults.standard
        let value = defaults.object(forKey: triggerKeyDefaultsKey) == nil
            ? defaultTriggerUsage : defaults.integer(forKey: triggerKeyDefaultsKey)
        return UInt32(truncatingIfNeeded: value)
    }

    private static var armTimeout: TimeInterval {
        let defaults = UserDefaults.standard
        let value = defaults.object(forKey: armTimeoutDefaultsKey) == nil
            ? defaultArmTimeout : defaults.double(forKey: armTimeoutDefaultsKey)
        return min(max(value, armTimeoutRange.lowerBound), armTimeoutRange.upperBound)
    }
    func start() {
        // Ask for Input Monitoring now, in the user session: a prompt cannot appear on the lock screen.
        if IOHIDCheckAccess(kIOHIDRequestTypeListenEvent) == kIOHIDAccessTypeUnknown {
            IOHIDRequestAccess(kIOHIDRequestTypeListenEvent)
        }
        HelperManager.shared.registerQuietly()
        let distributed = DistributedNotificationCenter.default()
        distributed.addObserver(
            self,
            selector: #selector(receivedScreenLocked),
            name: .init("com.apple.screenIsLocked"),
            object: nil
        )
        distributed.addObserver(
            self,
            selector: #selector(receivedScreenUnlocked),
            name: .init("com.apple.screenIsUnlocked"),
            object: nil
        )
    }

    func stop() {
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        generation &+= 1
        isAttempting = false
        stopKeyWatch()
    }

    // The configured trigger key (Backspace by default) on the lock screen requests an unlock. The password
    // field takes secure event input and macOS hides the lock screen's keystrokes from user processes
    // (event taps and HID alike), so the root helper reads the keyboards and reports decisions only.
    // The user-level watcher stays as a fallback for systems where it still receives keys.
    private func startKeyWatch() {
        stopKeyWatch()
        let trigger = Self.triggerUsage
        let watcher = KeyWatcher(triggerUsage: trigger) { [weak self] decision in
            self?.handle(trigger: decision == .trigger, source: "user")
        }
        watcher.start()
        keyWatcher = watcher
        HelperManager.shared.startKeyWatch(
            trigger: Int(trigger),
            decision: { [weak self] isTrigger in self?.handle(trigger: isTrigger, source: "helper") },
            done: { ok, message in Self.trace.notice("helper key watch ok=\(ok): \(message, privacy: .public)") }
        )
    }

    private func handle(trigger: Bool, source: String) {
        guard isLocked, isArmed else {
            Self.trace.notice("key ignored (\(source, privacy: .public)): locked=\(self.isLocked) armed=\(self.isArmed)")
            return
        }
        guard trigger else {
            isArmed = false   // the user is typing the password by hand
            Self.trace.notice("other key (\(source, privacy: .public)): disarmed")
            return
        }
        isArmed = false
        Self.trace.notice("trigger key (\(source, privacy: .public)): requesting unlock")
        requestUnlock()
    }

    private func stopKeyWatch() {
        isArmed = false
        keyWatcher?.stop()
        keyWatcher = nil
        HelperManager.shared.stopKeyWatch()
    }

    private func requestUnlock() {
        guard isLocked, !isAttempting else { return }
        generation &+= 1
        scheduleAttempt(generation: generation, delay: 0)
    }

    @objc private func receivedScreenLocked() {
        DispatchQueue.main.async {
            Self.trace.notice("screen locked; hidAccess=\(IOHIDCheckAccess(kIOHIDRequestTypeListenEvent).rawValue)")
            self.isLocked = true
            self.generation &+= 1
            self.isAttempting = false
            self.startKeyWatch()
            self.isArmed = true
            let session = self.generation
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.armTimeout) {
                guard self.generation == session, self.isArmed else { return }
                self.isArmed = false
                Self.trace.notice("arm timeout: disarmed")
            }
        }
    }

    @objc private func receivedScreenUnlocked() {
        DispatchQueue.main.async {
            Self.trace.notice("screen unlocked; user-level raw hid events=\(self.keyWatcher?.rawEvents ?? 0)")
            self.isLocked = false
            self.generation &+= 1
            self.isAttempting = false
            self.stopKeyWatch()
        }
    }

    private func scheduleAttempt(generation expected: UInt64, delay: TimeInterval) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            guard self.generation == expected else { return }
            self.attemptUnlock(generation: expected)
        }
    }

    private func attemptUnlock(generation expected: UInt64) {
        let checks: [(String, Bool)] = [
            ("enabled", Settings.shared.screenUnlockEnabled),
            ("enrolled", Status.enrolled),
            ("password", LoginPasswordStore.isConfigured),
            ("accessibility", LockScreenAccessibility.isTrusted),
            ("locked", isLocked),
            ("idle", !isAttempting),
            ("session", Self.isScreenActuallyLocked()),
        ]
        if let failed = checks.first(where: { !$0.1 }) {
            Self.trace.notice("attempt skipped: \(failed.0)")
            return
        }

        isAttempting = true
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Run.faceid(["verify", "--lock"], env: Settings.shared.env)
            DispatchQueue.main.async {
                    guard self.generation == expected, self.isLocked else {
                    self.isAttempting = false
                    return
                }
                guard result.code == 0,
                      result.out.split(whereSeparator: \.isWhitespace).contains("OK"),
                      Self.isScreenActuallyLocked()
                else {
                    Self.trace.notice("face check failed (code \(result.code))")
                    self.isAttempting = false
                    return
                }
                Self.trace.notice("face matched; typing password")
                self.injectStoredPassword(generation: expected)
            }
        }
    }

    private func injectStoredPassword(generation expected: UInt64) {
        wakeDisplay()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.10) {
            defer { self.isAttempting = false }
            let delivered = LockScreenPasswordDelivery.deliver(load: LoginPasswordStore.load, target: {
                guard self.generation == expected, self.isLocked,
                      Settings.shared.screenUnlockEnabled, Status.enrolled,
                      LockScreenAccessibility.isTrusted else { return nil }
                return LockScreenDestination.current()
            }, post: Self.postPassword)
            Self.trace.notice("password delivered=\(delivered)")
        }
    }

    private func wakeDisplay() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/caffeinate")
        process.arguments = ["-u", "-t", "1"]
        try? process.run()
    }

    private static func postPassword(_ data: Data, to destination: pid_t) {
        guard let password = String(data: data, encoding: .utf8),
              let source = CGEventSource(stateID: .hidSystemState)
        else { return }

        func tap(_ virtualKey: CGKeyCode) {
            CGEvent(keyboardEventSource: source, virtualKey: virtualKey, keyDown: true)?.postToPid(destination)
            CGEvent(keyboardEventSource: source, virtualKey: virtualKey, keyDown: false)?.postToPid(destination)
        }

        // loginwindow hides the password field until a key arrives and does not focus it
        // at once: a first key reveals it, the following ones are typed once it has focus.
        tap(51)
        Thread.sleep(forTimeInterval: 0.30)

        var characters = Array(password.utf16)
        defer {
            for index in characters.indices { characters[index] = 0 }
        }
        // One keystroke per character; a single event carrying the whole password is
        // treated as one key press by loginwindow.
        for index in characters.indices {
            var unit = [characters[index]]
            defer { unit[0] = 0 }
            for down in [true, false] {
                guard let event = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: down) else { continue }
                event.keyboardSetUnicodeString(stringLength: 1, unicodeString: &unit)
                event.postToPid(destination)
            }
            Thread.sleep(forTimeInterval: 0.012)
        }
        Thread.sleep(forTimeInterval: 0.05)
        tap(36)
    }

    private static func isScreenActuallyLocked() -> Bool {
        LockScreenDestination.sessionIsEligible
    }
}
