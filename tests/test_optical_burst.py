import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gateway_server.airgap.optical_burst import OpticalBurstEngine


def test_optical_burst_generation_and_reconstruction():
    # 5 KB payload
    raw_payload = b"ETIPOS_AIRGAP_TEST_DATA:" + os.urandom(5 * 1024)
    payload_id = "airgap-test-99"
    sig = "TEST_ED25519_GATEWAY_SIGNATURE_BASE64"

    frames = OpticalBurstEngine.generate_burst_frames(
        raw_payload, payload_id=payload_id, gateway_signature=sig, frame_size=300
    )

    assert len(frames) > 5
    assert frames[0]["i"] == 0
    assert frames[0]["t"] == len(frames)
    assert frames[0]["s"] == sig

    # Render QR data URI for first frame
    qr_uri = OpticalBurstEngine.render_frame_qr_png_base64(frames[0])
    assert qr_uri.startswith("data:image/png;base64,")

    # Render SVG for second frame
    svg_str = OpticalBurstEngine.render_frame_qr_svg(frames[1])
    assert "<svg" in svg_str

    # Test complete reconstruction from shuffled frame list
    shuffled = list(reversed(frames))
    reconstructed_bytes, reconstructed_sig = OpticalBurstEngine.reconstruct_from_frames(shuffled)

    assert reconstructed_bytes == raw_payload
    assert reconstructed_sig == sig


def test_optical_burst_missing_frame_error():
    raw_payload = b"Sample payload for loss testing"
    frames = OpticalBurstEngine.generate_burst_frames(raw_payload, payload_id="test", frame_size=10)

    if len(frames) > 1:
        # Drop frame 0
        incomplete = frames[1:]
        with pytest.raises(ValueError, match="Incomplete burst stream"):
            OpticalBurstEngine.reconstruct_from_frames(incomplete)


if __name__ == "__main__":
    pytest.main(["-v", __file__])

