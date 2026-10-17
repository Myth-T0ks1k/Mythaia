import SwiftUI

/// The Mythaia WingMark: three feather strokes fanning up and to the right
/// from one origin at the bottom left, in a 100 x 100 design space scaled to
/// the smaller side of the frame. Stroked, never filled, with round caps.
struct WingMark: Shape {
    /// One feather: a quadratic curve from the common origin.
    struct Feather {
        let control: CGPoint
        let end: CGPoint
        /// Reference stroke width in design units.
        let width: CGFloat
    }

    static let origin = CGPoint(x: 20, y: 82)
    static let feathers: [Feather] = [
        Feather(control: CGPoint(x: 21, y: 32), end: CGPoint(x: 82, y: 20), width: 8.5),
        Feather(control: CGPoint(x: 29, y: 47), end: CGPoint(x: 69, y: 38), width: 8.0),
        Feather(control: CGPoint(x: 36, y: 61), end: CGPoint(x: 57, y: 55), width: 7.5),
    ]

    /// Which feather to draw; nil draws all three as one path.
    var only: Int? = nil

    func path(in rect: CGRect) -> Path {
        let s = min(rect.width, rect.height) / 100
        var path = Path()
        for (index, feather) in WingMark.feathers.enumerated() {
            if let only = only, only != index { continue }
            path.move(to: CGPoint(x: rect.minX + WingMark.origin.x * s, y: rect.minY + WingMark.origin.y * s))
            path.addQuadCurve(
                to: CGPoint(x: rect.minX + feather.end.x * s, y: rect.minY + feather.end.y * s),
                control: CGPoint(x: rect.minX + feather.control.x * s, y: rect.minY + feather.control.y * s)
            )
        }
        return path
    }
}

/// The WingMark drawn at its reference weights in one colour.
struct WingMarkView: View {
    var color: Color
    var strokeScale: CGFloat = 1

    var body: some View {
        GeometryReader { geometry in
            let s = min(geometry.size.width, geometry.size.height) / 100
            ZStack {
                ForEach(0..<WingMark.feathers.count, id: \.self) { index in
                    WingMark(only: index)
                        .stroke(color, style: StrokeStyle(
                            lineWidth: WingMark.feathers[index].width * s * strokeScale,
                            lineCap: .round
                        ))
                }
            }
        }
        .accessibilityHidden(true)
    }
}
