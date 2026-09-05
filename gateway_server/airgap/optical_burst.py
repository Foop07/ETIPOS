"""
ETIPOS Optical Air-Gap Burst Engine (Gateway Node 2 -> Receiver Node 3)
Implements:
  - Scaife et al. (2014): "Air-Gapped Data Exfiltration and Transfer via Optical Channels"
  - Generates multi-frame QR code animated bursts for transmitting sanitized payloads
    across zero-RF air gaps without radio emissions.
"""

import io
import zlib
import base64
import json
from typing import List, Dict, Any, Tuple
import qrcode
from qrcode.image.svg import SvgPathImage


class OpticalBurstEngine:
    """Encodes and decodes multi-frame QR bursts for optical air-gap data transmission."""

    # Default payload characters per QR frame (balanced for high-speed camera capture at 15-30 FPS)
    FRAME_PAYLOAD_SIZE = 350

    @classmethod
    def generate_burst_frames(
        cls,
        payload_bytes: bytes,
        payload_id: str,
        gateway_signature: str = "",
        frame_size: int = FRAME_PAYLOAD_SIZE
    ) -> List[Dict[str, Any]]:
        """
        Splits payload into sequence of optical burst frames with CRC32 checksums.
        """
        # Compress payload before burst transmission
        compressed = zlib.compress(payload_bytes, level=9)
        b64_data = base64.b64encode(compressed).decode('utf-8')

        total_length = len(b64_data)
        num_frames = (total_length + frame_size - 1) // frame_size if total_length > 0 else 1

        frames = []
        for i in range(num_frames):
            start = i * frame_size
            end = min(start + frame_size, total_length)
            chunk = b64_data[start:end]
            
            crc = format(zlib.crc32(chunk.encode('utf-8')) & 0xFFFFFFFF, '08x')

            frame_obj = {
                "v": 1,                     # Protocol version
                "p": payload_id,            # Payload UUID
                "i": i,                     # Frame index
                "t": num_frames,            # Total frames
                "c": crc,                   # CRC32
                "d": chunk,                 # Compressed segment
                "s": gateway_signature if i == 0 else ""  # Header includes Gateway signature
            }
            frames.append(frame_obj)

        return frames

    @classmethod
    def render_frame_qr_png_base64(cls, frame_data: Dict[str, Any]) -> str:
        """Renders a single optical frame as a PNG base64 image data URI."""
        compact_json = json.dumps(frame_data, separators=(',', ':'))
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(compact_json)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64_img = base64.b64encode(buf.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{b64_img}"

    @classmethod
    def render_frame_qr_svg(cls, frame_data: Dict[str, Any]) -> str:
        """Renders a single optical frame as an SVG string."""
        compact_json = json.dumps(frame_data, separators=(',', ':'))
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            image_factory=SvgPathImage,
            border=2
        )
        qr.add_data(compact_json)
        qr.make(fit=True)
        img = qr.make_image()
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode('utf-8')

    @classmethod
    def reconstruct_from_frames(cls, frame_list: List[Dict[str, Any]]) -> Tuple[bytes, str]:
        """
        Reassembles payload bytes from captured optical frames.
        Returns (payload_bytes, gateway_signature).
        """
        if not frame_list:
            raise ValueError("No frames provided")

        sorted_frames = sorted(frame_list, key=lambda f: f["i"])
        total_frames = sorted_frames[0]["t"]
        payload_id = sorted_frames[0]["p"]
        signature = sorted_frames[0].get("s", "")

        # Validate complete frame reception
        received_indices = {f["i"] for f in sorted_frames}
        expected_indices = set(range(total_frames))
        missing = expected_indices - received_indices
        if missing:
            raise ValueError(f"Incomplete burst stream: missing frames {missing}")

        assembled_b64 = []
        for f in sorted_frames:
            # Verify CRC32
            chunk = f["d"]
            calc_crc = format(zlib.crc32(chunk.encode('utf-8')) & 0xFFFFFFFF, '08x')
            if calc_crc != f["c"]:
                raise ValueError(f"CRC32 mismatch on frame {f['i']}: expected {f['c']}, got {calc_crc}")
            assembled_b64.append(chunk)

        full_b64 = "".join(assembled_b64)
        compressed = base64.b64decode(full_b64)
        decompressed = zlib.decompress(compressed)
        return decompressed, signature

