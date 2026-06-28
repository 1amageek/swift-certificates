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

import XCTest
@testable import X509

final class IPAddressParsingTests: XCTestCase {
    func testIPv4ParserAcceptsValidAddresses() {
        XCTAssertEqual(X509IPAddressParser.parseIPv4Address("0.0.0.0"), [0, 0, 0, 0])
        XCTAssertEqual(X509IPAddressParser.parseIPv4Address("192.168.0.1"), [192, 168, 0, 1])
        XCTAssertEqual(X509IPAddressParser.parseIPv4Address("255.255.255.255"), [255, 255, 255, 255])
    }

    func testIPv4ParserRejectsInvalidAddresses() {
        let invalidAddresses = [
            "",
            "1.2.3",
            "1.2.3.4.5",
            "256.0.0.1",
            "1..2.3",
            "1.2.3.a",
            "1.2.3.-1"
        ]

        for address in invalidAddresses {
            XCTAssertNil(X509IPAddressParser.parseIPv4Address(address), address)
        }
    }

    func testIPv6ParserAcceptsValidAddresses() {
        XCTAssertEqual(
            X509IPAddressParser.parseIPv6Address("::1"),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        )
        XCTAssertEqual(
            X509IPAddressParser.parseIPv6Address("2001:db8::1"),
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        )
        XCTAssertEqual(
            X509IPAddressParser.parseIPv6Address("::ffff:192.0.2.128"),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0, 0x02, 0x80]
        )
        XCTAssertEqual(
            X509IPAddressParser.parseIPv6Address("2001:db8:0:0:0:0:2:1"),
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]
        )
    }

    func testIPv6ParserRejectsInvalidAddresses() {
        let invalidAddresses = [
            "",
            ":::",
            "1::2::3",
            "2001:db8::1%en0",
            "2001:db8::192.0.2.999",
            "1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:8:9",
            "gggg::1"
        ]

        for address in invalidAddresses {
            XCTAssertNil(X509IPAddressParser.parseIPv6Address(address), address)
        }
    }
}
