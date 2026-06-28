//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@usableFromInline
enum X509IPAddressParser {
    @usableFromInline
    static func parseIPv4Address(_ string: String) -> [UInt8]? {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            return nil
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(4)

        for part in parts {
            guard !part.isEmpty else {
                return nil
            }

            var value = 0
            for character in part.utf8 {
                guard character >= x509IPAddressASCIIZero, character <= x509IPAddressASCIINine else {
                    return nil
                }

                value = (value * 10) + Int(character - x509IPAddressASCIIZero)
                guard value <= Int(UInt8.max) else {
                    return nil
                }
            }

            bytes.append(UInt8(value))
        }

        return bytes
    }

    @usableFromInline
    static func parseIPv6Address(_ string: String) -> [UInt8]? {
        guard !string.isEmpty, !string.utf8.contains(x509IPAddressASCIIPercent) else {
            return nil
        }

        let compressedRange = firstDoubleColonRange(in: string)
        if let compressedRange {
            let searchStart = compressedRange.upperBound
            guard firstDoubleColonRange(in: string, startingAt: searchStart) == nil else {
                return nil
            }

            let head = string[..<compressedRange.lowerBound]
            let tail = string[compressedRange.upperBound...]
            guard let headGroups = parseIPv6Groups(head),
                let tailGroups = parseIPv6Groups(tail)
            else {
                return nil
            }

            let explicitGroupCount = headGroups.count + tailGroups.count
            guard explicitGroupCount < 8 else {
                return nil
            }

            let groups = headGroups + Array(repeating: UInt16(0), count: 8 - explicitGroupCount) + tailGroups
            return ipv6Bytes(from: groups)
        } else {
            guard let groups = parseIPv6Groups(string[...]), groups.count == 8 else {
                return nil
            }

            return ipv6Bytes(from: groups)
        }
    }

    @usableFromInline
    static func parseIPv6Groups(_ string: Substring) -> [UInt16]? {
        guard !string.isEmpty else {
            return []
        }

        let parts = string.split(separator: ":", omittingEmptySubsequences: false)
        var groups: [UInt16] = []
        groups.reserveCapacity(8)

        for (index, part) in parts.enumerated() {
            guard !part.isEmpty else {
                return nil
            }

            if part.contains(".") {
                guard index == parts.index(before: parts.endIndex),
                    let ipv4Bytes = parseIPv4Address(String(part))
                else {
                    return nil
                }

                groups.append((UInt16(ipv4Bytes[0]) << 8) | UInt16(ipv4Bytes[1]))
                groups.append((UInt16(ipv4Bytes[2]) << 8) | UInt16(ipv4Bytes[3]))
            } else {
                guard let group = parseIPv6Group(part) else {
                    return nil
                }

                groups.append(group)
            }

            guard groups.count <= 8 else {
                return nil
            }
        }

        return groups
    }

    @usableFromInline
    static func parseIPv6Group(_ string: Substring) -> UInt16? {
        guard !string.isEmpty, string.count <= 4 else {
            return nil
        }

        var value: UInt16 = 0
        for character in string.utf8 {
            guard let nibble = hexValue(of: character) else {
                return nil
            }

            value = (value << 4) | UInt16(nibble)
        }

        return value
    }

    @usableFromInline
    static func ipv6Bytes(from groups: [UInt16]) -> [UInt8]? {
        guard groups.count == 8 else {
            return nil
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(16)
        for group in groups {
            bytes.append(UInt8(group >> 8))
            bytes.append(UInt8(group & 0xff))
        }
        return bytes
    }

    @usableFromInline
    static func hexValue(of character: UInt8) -> UInt8? {
        switch character {
        case x509IPAddressASCIIZero...x509IPAddressASCIINine:
            return character - x509IPAddressASCIIZero
        case x509IPAddressASCIILowercaseA...x509IPAddressASCIILowercaseF:
            return character - x509IPAddressASCIILowercaseA + 10
        case x509IPAddressASCIIUppercaseA...x509IPAddressASCIIUppercaseF:
            return character - x509IPAddressASCIIUppercaseA + 10
        default:
            return nil
        }
    }

    @usableFromInline
    static func firstDoubleColonRange(
        in string: String,
        startingAt startIndex: String.Index? = nil
    ) -> Range<String.Index>? {
        var index = startIndex ?? string.startIndex

        while index < string.endIndex {
            let nextIndex = string.index(after: index)
            guard nextIndex < string.endIndex else {
                return nil
            }

            if string[index] == ":", string[nextIndex] == ":" {
                return index..<string.index(after: nextIndex)
            }

            index = nextIndex
        }

        return nil
    }
}

@usableFromInline
let x509IPAddressASCIIZero = UInt8(ascii: "0")
@usableFromInline
let x509IPAddressASCIINine = UInt8(ascii: "9")
@usableFromInline
let x509IPAddressASCIILowercaseA = UInt8(ascii: "a")
@usableFromInline
let x509IPAddressASCIILowercaseF = UInt8(ascii: "f")
@usableFromInline
let x509IPAddressASCIIUppercaseA = UInt8(ascii: "A")
@usableFromInline
let x509IPAddressASCIIUppercaseF = UInt8(ascii: "F")
@usableFromInline
let x509IPAddressASCIIPercent = UInt8(ascii: "%")
