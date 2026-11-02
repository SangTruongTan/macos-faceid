// KeyWatcher — reads keyboards at the HID level and reduces every press to a decision:
// the configured trigger key, or any other key. Compiled into the app (user-level fallback)
// and into the root helper, which is the only process macOS lets read keys on the lock screen.
// Key values are never logged, stored or sent anywhere: while locked they are password keystrokes.
import Foundation
import IOKit.hid
import os

final class KeyWatcher {
    enum Decision { case trigger, other }

    private static let trace = Logger(subsystem: "com.lorenzo.Mugshot", category: "keywatch")
    // One physical press can reach the callback through several HID elements.
    private static let debounce: TimeInterval = 0.04
    // Keys still in flight from the lock shortcut (Ctrl+Cmd+Q) must not count.
    private static let settle: TimeInterval = 0.4
    // Left/right Control and Command: shortcuts such as Ctrl+Cmd+Q are not password typing.
    private static let shortcutModifiers: Set<UInt32> = [0xE0, 0xE3, 0xE4, 0xE7]

    private let triggerUsage: UInt32
    private let onDecision: (Decision) -> Void
    private var manager: IOHIDManager?
    private var devices: [IOHIDDevice] = []
    private var modifiersDown = Set<UInt32>()
    private var lastKey: (usage: UInt32, at: Date)?
    private var startedAt = Date.distantPast
    private(set) var rawEvents = 0
    private(set) var failedOpens = 0

    var openedDevices: Int { devices.count }
    /// 0 granted, 1 denied, 2 not determined (IOHIDAccessType raw values).
    var listenAccess: Int { Int(IOHIDCheckAccess(kIOHIDRequestTypeListenEvent).rawValue) }

    init(triggerUsage: UInt32, onDecision: @escaping (Decision) -> Void) {
        self.triggerUsage = triggerUsage
        self.onDecision = onDecision
    }

    deinit { stop() }

    /// Must run on the main thread: devices are scheduled on the main run loop.
    func start() {
        stop()
        startedAt = Date()
        rawEvents = 0
        failedOpens = 0
        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        IOHIDManagerSetDeviceMatching(manager, [
            kIOHIDDeviceUsagePageKey: kHIDPage_GenericDesktop,
            kIOHIDDeviceUsageKey: kHIDUsage_GD_Keyboard,
        ] as CFDictionary)
        // Remappers such as Karabiner-Elements seize the physical keyboards exclusively, which
        // makes IOHIDManagerOpen fail for the whole set. Devices are opened one by one so the
        // ones that refuse are skipped and the virtual keyboard they re-emit through still works.
        IOHIDManagerRegisterDeviceMatchingCallback(manager, { context, _, _, device in
            guard let context else { return }
            Unmanaged<KeyWatcher>.fromOpaque(context).takeUnretainedValue().attach(device)
        }, Unmanaged.passUnretained(self).toOpaque())
        IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue)
        _ = IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
        self.manager = manager
    }

    func stop() {
        for device in devices {
            IOHIDDeviceUnscheduleFromRunLoop(device, CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue)
            IOHIDDeviceClose(device, IOOptionBits(kIOHIDOptionsTypeNone))
        }
        devices.removeAll()
        if let manager {
            IOHIDManagerUnscheduleFromRunLoop(manager, CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue)
            IOHIDManagerClose(manager, IOOptionBits(kIOHIDOptionsTypeNone))
        }
        manager = nil
        modifiersDown.removeAll()
        lastKey = nil
    }

    private func attach(_ device: IOHIDDevice) {
        let result = IOHIDDeviceOpen(device, IOOptionBits(kIOHIDOptionsTypeNone))
        let name = IOHIDDeviceGetProperty(device, kIOHIDProductKey as CFString) as? String ?? "?"
        Self.trace.notice("open \(name, privacy: .public): 0x\(String(UInt32(bitPattern: result), radix: 16), privacy: .public)")
        guard result == kIOReturnSuccess else { failedOpens += 1; return }
        IOHIDDeviceRegisterInputValueCallback(device, { context, _, _, value in
            guard let context else { return }
            Unmanaged<KeyWatcher>.fromOpaque(context).takeUnretainedValue().receive(value)
        }, Unmanaged.passUnretained(self).toOpaque())
        IOHIDDeviceScheduleWithRunLoop(device, CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue)
        devices.append(device)
    }

    private func receive(_ value: IOHIDValue) {
        rawEvents += 1
        let element = IOHIDValueGetElement(value)
        guard IOHIDElementGetUsagePage(element) == UInt32(kHIDPage_KeyboardOrKeypad) else { return }
        let raw = IOHIDValueGetIntegerValue(value)
        // Keyboards report keys either as one variable element per key (value 1/0) or as an
        // array whose value is the key code (0 when released).
        let usage = IOHIDElementIsArray(element) ? UInt32(truncatingIfNeeded: raw) : IOHIDElementGetUsage(element)
        handle(usage: usage, pressed: raw != 0)
    }

    private func handle(usage: UInt32, pressed: Bool) {
        // 0xE0...0xE7 are modifiers; 0x00...0x03 are rollover/error markers.
        if usage >= 0xE0 && usage <= 0xE7 {
            if pressed { modifiersDown.insert(usage) } else { modifiersDown.remove(usage) }
            return
        }
        guard pressed, usage > 0x03 else { return }
        let stamp = Date()
        if let lastKey, lastKey.usage == usage, stamp.timeIntervalSince(lastKey.at) < Self.debounce { return }
        lastKey = (usage, stamp)
        if !modifiersDown.isDisjoint(with: Self.shortcutModifiers)
            || stamp.timeIntervalSince(startedAt) < Self.settle { return }
        onDecision(usage == triggerUsage ? .trigger : .other)
    }
}
