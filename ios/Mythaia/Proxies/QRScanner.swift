import SwiftUI
import AVFoundation
import UIKit

/// A sheet that reads one QR code with the camera and hands its text back.
@MainActor
struct QRScannerSheet: View {
    let onFound: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var access: CameraAccess = .unknown

    enum CameraAccess {
        case unknown
        case granted
        case denied
        case unavailable
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                stateView
            }
            .navigationTitle(Text("Scan your QR code"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .task {
            await checkAccess()
        }
    }

    @ViewBuilder
    private var stateView: some View {
        switch access {
        case .unknown:
            ProgressView().tint(.white)
        case .granted:
            ZStack {
                QRCameraView(onFound: { code in
                    onFound(code)
                    dismiss()
                })
                .ignoresSafeArea()
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.85), lineWidth: 3)
                    .frame(width: 240, height: 240)
                    .allowsHitTesting(false)
            }
        case .denied:
            messageView(
                text: String(localized: "Camera access is blocked. Allow it in the app settings to scan QR codes."),
                showSettings: true
            )
        case .unavailable:
            messageView(text: String(localized: "No camera is available on this device."), showSettings: false)
        }
    }

    private func messageView(text: String, showSettings: Bool) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "camera")
                .font(.largeTitle)
                .foregroundColor(.white.opacity(0.8))
            Text(verbatim: text)
                .font(.body)
                .foregroundColor(.white)
                .multilineTextAlignment(.center)
            if showSettings {
                Button("Open settings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        openURL(url)
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(32)
    }

    private func checkAccess() async {
        guard AVCaptureDevice.default(for: .video) != nil else {
            access = .unavailable
            return
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            access = .granted
        case .notDetermined:
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            access = granted ? .granted : .denied
        default:
            access = .denied
        }
    }
}

/// The camera preview with a QR reader on it.
struct QRCameraView: UIViewControllerRepresentable {
    let onFound: (String) -> Void

    func makeUIViewController(context: Context) -> QRCameraController {
        let controller = QRCameraController()
        controller.onFound = onFound
        return controller
    }

    func updateUIViewController(_ controller: QRCameraController, context: Context) {
        controller.onFound = onFound
    }
}

final class QRCameraController: UIViewController {
    var onFound: ((String) -> Void)?
    private let session = AVCaptureSession()
    private let reader = QRMetadataReader()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var delivered = false
    private let sessionQueue = DispatchQueue(label: "mythaia.qr.session")

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        reader.onCode = { [weak self] text in
            self?.deliver(text)
        }
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(reader, queue: DispatchQueue.main)
        if output.availableMetadataObjectTypes.contains(.qr) {
            output.metadataObjectTypes = [.qr]
        }
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        previewLayer = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let session = self.session
        sessionQueue.async {
            if !session.isRunning { session.startRunning() }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let session = self.session
        sessionQueue.async {
            if session.isRunning { session.stopRunning() }
        }
    }

    private func deliver(_ text: String) {
        guard !delivered else { return }
        delivered = true
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        onFound?(text)
    }
}

/// Receives what the camera reads, on the main queue, and passes on the
/// first QR code's text.
final class QRMetadataReader: NSObject, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        for object in metadataObjects {
            guard let code = object as? AVMetadataMachineReadableCodeObject, code.type == .qr,
                  let text = code.stringValue, !text.isEmpty else { continue }
            onCode?(text)
            return
        }
    }
}
