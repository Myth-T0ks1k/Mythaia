import XCTest
@testable import MythaiaKit

/// The fragmentation formats a panel actually sends.
final class ModelFragmentSettingsTests: XCTestCase {

    private let finalMask = #"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3"],"delays":["1"],"maxSplit":"2"}}]}"#

    func testFmDocumentWithLengths3AndMaxSplit2ParsesToThreeBytesThenTheRest() throws {
        let settings = try XCTUnwrap(FragmentSettings.fromFinalMask(finalMask))
        XCTAssertTrue(settings.isEnabled)
        XCTAssertEqual(settings.lengthRanges, [3...3])
        XCTAssertEqual(settings.delayRanges, [1...1])
        XCTAssertEqual(settings.maxSplit, 2)
    }

    func testFmWithRangeTextsAndPerPieceListsIsKeptPerPiece() throws {
        let doc = #"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5","6-8","10-20"],"delays":["10-20"],"maxSplit":"3-6"}}]}"#
        let settings = try XCTUnwrap(FragmentSettings.fromFinalMask(doc))
        XCTAssertEqual(settings.lengthRanges, [3...5, 6...8, 10...20])
        XCTAssertEqual(settings.delayRanges, [10...20])
        XCTAssertEqual(settings.maxSplit, 6)
    }

    func testFmWithoutATcpFragmentMaskIsNil() {
        XCTAssertNil(FragmentSettings.fromFinalMask(#"{"udp":[{"type":"salamander","settings":{"password":"x"}}]}"#))
        XCTAssertNil(FragmentSettings.fromFinalMask("not json"))
    }

    func testShareLinkFormAcceptsAnOptionalMaxSplit() throws {
        let settings = try XCTUnwrap(FragmentSettings.fromShareLink("1-10,5-20,tlshello,2"))
        XCTAssertEqual(settings.lengthRange, 1...10)
        XCTAssertEqual(settings.intervalRange, 5...20)
        XCTAssertEqual(settings.maxSplit, 2)
        XCTAssertEqual(FragmentSettings.fromShareLink("1-10,5-20,tlshello")?.maxSplit, 0)
        XCTAssertNil(FragmentSettings.fromShareLink("0,5,tlshello"))
        XCTAssertNil(FragmentSettings.fromShareLink("10-5,5,tlshello"))
        XCTAssertNil(FragmentSettings.fromShareLink("1,5"))
    }

    func testFmWithSingularLengthAndDelayReadsLikeThePluralLists() throws {
        // The spelling one real provider uses next to the plural one.
        let singular = try XCTUnwrap(FragmentSettings.fromFinalMask(
            #"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","maxSplit":"2","length":"3","delay":"1"}}]}"#
        ))
        XCTAssertEqual(singular.lengthRanges, [3...3])
        XCTAssertEqual(singular.delayRanges, [1...1])
        XCTAssertEqual(singular.maxSplit, 2)

        // Bare numbers mean the same as the strings.
        let numbers = try XCTUnwrap(FragmentSettings.fromFinalMask(
            #"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":5,"delay":2,"maxSplit":3}}]}"#
        ))
        XCTAssertEqual(numbers.lengthRanges, [5...5])
        XCTAssertEqual(numbers.delayRanges, [2...2])
        XCTAssertEqual(numbers.maxSplit, 3)
    }

    func testFinalMaskExportSaysWhatWasParsed() throws {
        let settings = try XCTUnwrap(FragmentSettings.fromFinalMask(finalMask))
        let back = try XCTUnwrap(FragmentSettings.fromFinalMask(settings.toFinalMaskJson()))
        XCTAssertEqual(back.lengthRanges, settings.lengthRanges)
        XCTAssertEqual(back.delayRanges, settings.delayRanges)
        XCTAssertEqual(back.maxSplit, settings.maxSplit)
        XCTAssertEqual(
            settings.toFinalMaskJson(),
            #"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3"],"delays":["1"],"maxSplit":"2"}}]}"#
        )
    }

    func testTheShareLinkValueIsTheFirstStep() throws {
        let settings = try XCTUnwrap(FragmentSettings.fromFinalMask(finalMask))
        XCTAssertEqual(settings.toShareLinkValue(), "3,1,tlshello,2")
        XCTAssertEqual(FragmentSettings().toShareLinkValue(), "100-200,10-20,tlshello")
    }

    func testRangesTypedBackwardsAreReadTheRightWayRound() {
        let settings = FragmentSettings(minLength: 50, maxLength: 0, minInterval: 9, maxInterval: 3)
        XCTAssertEqual(settings.lengthRange, 1...50)
        XCTAssertEqual(settings.intervalRange, 3...9)
    }
}
