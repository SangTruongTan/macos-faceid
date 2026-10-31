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
    private var hidManager: IOHIDManager?
    private var modifiersDown = Set<UInt32>()
    private var lastKey: (usage: UInt32, at: Date)?
    // One physical press can reach the callback through several HID elements.
    private static let keyDebounce: TimeInterval = 0.04
    private var lockedAt = Date.distantPast
    // Keys still in flight from the lock shortcut (Ctrl+Cmd+Q) must not disarm the unlock.
    private static let lockShortcutSettle: TimeInterval = 0.4
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
    // Left/right Control and Command: shortcuts such as Ctrl+Cmd+Q are not password typing.
    private static let shortcutModifierUsages: Set<UInt32> = [0xE0, 0xE3, 0xE4, 0xE7]

    func start() {
        // Ask for Input Monitoring now, in the user session: a prompt cannot appear on the lock screen.
        if IOHIDCheckAccess(kIOHIDRequestTypeListenEvent) == kIOHIDAccessTypeUnknown {
            IOHIDRequestAccess(kIOHIDRequestTypeListenEvent)
        }
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

    // The configured trigger key (Backspace by default) on the lock screen requests an unlock. The password field
    // takes secure event input, which hides later keystrokes from NSEvent monitors and event
    // taps, so the keyboard is read at the HID level (Input Monitoring permission).
    private func startKeyWatch() {
        stopKeyWatch()
        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        IOHIDManagerSetDeviceMatching(manager, [
            kIOHIDDeviceUsagePageKey: kHIDPage_GenericDesktop,
            kIOHIDDeviceUsageKey: kHIDUsage_GD_Keyboard,
        ] as CFDictionary)
        let context = Unmanaged.passUnretained(self).toOpaque()
        IOHIDManagerRegisterInputValueCallback(manager, { context, _, _, value in
            guard let context else { return }
            let element = IOHIDValueGetElement(value)
            guard IOHIDElementGetUsagePage(element) == UInt32(kHIDPage_KeyboardOrKeypad) else { return }
            let raw = IOHIDValueGetIntegerValue(value)
            // Keyboards report keys either as one variable element per key (value 1/0) or as an
            // array whose value is the key code (0 when released).
            let isArray = IOHIDElementIsArray(element)
            let usage = isArray ? UInt32(truncatingIfNeeded: raw) : IOHIDElementGetUsage(element)
            let pressed = raw != 0
            let coordinator = Unmanaged<LockScreenUnlockCoordinator>.fromOpaque(context).takeUnretainedValue()
            DispatchQueue.main.async { coordinator.handleHIDKey(usage: usage, pressed: pressed) }
        }, context)
        IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue)
        IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
        hidManager = manager
    }

    private func handleHIDKey(usage: UInt32, pressed: Bool) {
        // 0xE0...0xE7 are modifiers; 0x00...0x03 are rollover/error markers.
        if usage >= 0xE0 && usage <= 0xE7 {
            if pressed { modifiersDown.insert(usage) } else { modifiersDown.remove(usage) }
            return
        }
        guard pressed, usage > 0x03, usage < 0xE0 || usage > 0xE7 else { return }
        let stamp = Date()
        if let lastKey, lastKey.usage == usage, stamp.timeIntervalSince(lastKey.at) < Self.keyDebounce { return }
        lastKey = (usage, stamp)
        guard isLocked, isArmed else {
            Self.trace.notice("key ignored: locked=\(self.isLocked) armed=\(self.isArmed)")
            return
        }
        if !modifiersDown.isDisjoint(with: Self.shortcutModifierUsages)
            || Date().timeIntervalSince(lockedAt) < Self.lockShortcutSettle {
            Self.trace.notice("key ignored: shortcut modifier or lock settle")
            return
        }
        guard usage == Self.triggerUsage else {
            isArmed = false   // the user is typing the password by hand
            Self.trace.notice("other key: disarmed")
            return
        }
        isArmed = false
        Self.trace.notice("trigger key: requesting unlock")
        requestUnlock()
    }

    private func stopKeyWatch() {
        isArmed = false
        modifiersDown.removeAll()
        lastKey = nil
        if let hidManager {
            IOHIDManagerUnscheduleFromRunLoop(hidManager, CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue)
            IOHIDManagerClose(hidManager, IOOptionBits(kIOHIDOptionsTypeNone))
        }
        hidManager = nil
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
            self.lockedAt = Date()
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
            Self.trace.notice("screen unlocked")
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
