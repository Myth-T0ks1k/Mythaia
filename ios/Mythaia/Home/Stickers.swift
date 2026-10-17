import SwiftUI

/// The small drawings along the edges of the home screen while the tunnel is
/// up, drawn in the WingMark's hand: round-capped strokes in one colour. A
/// red cross takes their place for a moment when a connection fails.
enum Sticker: CaseIterable {
    case sun, moon, star, cloud, feather, leaf, bolt, heart, redX

    /// Each weekday has its own quiet set (Monday first).
    static func forToday(_ date: Date = Date()) -> [Sticker] {
        let sets: [[Sticker]] = [
            [.sun, .cloud, .feather, .leaf],
            [.moon, .star, .feather, .cloud],
            [.bolt, .feather, .sun, .star],
            [.leaf, .heart, .feather, .sun],
            [.star, .cloud, .moon, .feather],
            [.feather, .bolt, .leaf, .cloud],
            [.sun, .heart, .feather, .star],
        ]
        // Calendar weekday: 1 is Sunday.
        let weekday = Calendar(identifier: .gregorian).component(.weekday, from: date)
        let mondayFirst = (weekday + 5) % 7
        return sets[mondayFirst]
    }
}

struct EdgeStickers: View {
    let visible: Bool
    let failed: Bool

    var body: some View {
        GeometryReader { geometry in
            let stickers = failed ? Array(repeating: Sticker.redX, count: 4) : Sticker.forToday()
            let color = failed ? Palette.error : Palette.lightAzure.opacity(0.9)
            HStack {
                column(stickers, color: color, largeFirst: true)
                    .padding(.leading, 10)
                Spacer()
                column(stickers.reversed(), color: color, largeFirst: false)
                    .padding(.trailing, 10)
            }
            .frame(height: geometry.size.height * 0.7)
            .frame(maxHeight: .infinity)
        }
        .opacity(visible ? 1 : 0)
        .animation(.easeInOut(duration: visible ? 0.5 : 0.3), value: visible)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private func column(_ stickers: [Sticker], color: Color, largeFirst: Bool) -> some View {
        VStack {
            ForEach(Array(stickers.enumerated()), id: \.offset) { index, sticker in
                let large = (index % 2 == 0) == largeFirst
                Spacer(minLength: 0)
                StickerGlyph(sticker: sticker, color: color)
                    .frame(width: large ? 34 : 26, height: large ? 34 : 26)
                    .opacity(failed ? 0.95 : 0.55)
                Spacer(minLength: 0)
            }
        }
    }
}

/// One sticker in a 100 x 100 design space, scaled to its frame.
struct StickerGlyph: View {
    let sticker: Sticker
    let color: Color

    var body: some View {
        GeometryReader { geometry in
            let s = min(geometry.size.width, geometry.size.height) / 100
            let style = StrokeStyle(lineWidth: 7 * s, lineCap: .round, lineJoin: .round)
            if sticker == .feather {
                WingMarkView(color: color)
            } else {
                StickerShape(sticker: sticker)
                    .stroke(color, style: style)
            }
        }
    }
}

private struct StickerShape: Shape {
    let sticker: Sticker

    func path(in rect: CGRect) -> Path {
        let s = min(rect.width, rect.height) / 100
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.minX + x * s, y: rect.minY + y * s)
        }
        var path = Path()
        switch sticker {
        case .sun:
            path.addEllipse(in: CGRect(x: rect.minX + 32 * s, y: rect.minY + 32 * s, width: 36 * s, height: 36 * s))
            for i in 0..<8 {
                let a = Double(i) * Double.pi / 4
                path.move(to: p(50 + 28 * CGFloat(cos(a)), 50 + 28 * CGFloat(sin(a))))
                path.addLine(to: p(50 + 40 * CGFloat(cos(a)), 50 + 40 * CGFloat(sin(a))))
            }
        case .moon:
            path.move(to: p(62, 14))
            path.addCurve(to: p(58, 86), control1: p(30, 20), control2: p(22, 68))
            path.addCurve(to: p(62, 14), control1: p(38, 72), control2: p(40, 30))
            path.closeSubpath()
        case .star:
            for i in 0..<10 {
                let r: CGFloat = i % 2 == 0 ? 38 : 16
                let a = -Double.pi / 2 + Double(i) * Double.pi / 5
                let point = p(50 + r * CGFloat(cos(a)), 52 + r * CGFloat(sin(a)))
                if i == 0 { path.move(to: point) } else { path.addLine(to: point) }
            }
            path.closeSubpath()
        case .cloud:
            path.move(to: p(26, 70))
            path.addCurve(to: p(30, 46), control1: p(8, 70), control2: p(10, 44))
            path.addCurve(to: p(64, 42), control1: p(32, 26), control2: p(60, 24))
            path.addCurve(to: p(72, 70), control1: p(84, 38), control2: p(92, 66))
            path.closeSubpath()
        case .leaf:
            path.move(to: p(22, 80))
            path.addCurve(to: p(82, 20), control1: p(20, 40), control2: p(50, 18))
            path.addCurve(to: p(22, 80), control1: p(84, 54), control2: p(60, 82))
            path.closeSubpath()
            path.move(to: p(24, 78))
            path.addLine(to: p(74, 28))
        case .bolt:
            path.move(to: p(58, 10))
            path.addLine(to: p(30, 56))
            path.addLine(to: p(50, 56))
            path.addLine(to: p(42, 90))
            path.addLine(to: p(72, 42))
            path.addLine(to: p(52, 42))
            path.closeSubpath()
        case .heart:
            path.move(to: p(50, 84))
            path.addCurve(to: p(36, 22), control1: p(14, 58), control2: p(14, 24))
            path.addCurve(to: p(50, 34), control1: p(44, 22), control2: p(48, 28))
            path.addCurve(to: p(64, 22), control1: p(52, 28), control2: p(56, 22))
            path.addCurve(to: p(50, 84), control1: p(86, 24), control2: p(86, 58))
            path.closeSubpath()
        case .redX:
            path.addEllipse(in: CGRect(x: rect.minX + 10 * s, y: rect.minY + 10 * s, width: 80 * s, height: 80 * s))
            path.move(to: p(32, 32))
            path.addLine(to: p(68, 68))
            path.move(to: p(68, 32))
            path.addLine(to: p(32, 68))
        case .feather:
            path = WingMark().path(in: rect)
        }
        return path
    }
}
