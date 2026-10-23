from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, output_path):
    """Create a simple ETIPOS icon"""
    # Create image with gradient-like background
    img = Image.new('RGB', (size, size), color='#667eea')
    draw = ImageDraw.Draw(img)
    
    # Draw gradient effect
    for i in range(size):
        color_val = int(102 + (118 - 102) * (i / size))
        draw.line([(0, i), (size, i)], fill=(color_val, 126, 234))
    
    # Draw a circle in the center
    circle_margin = size // 6
    draw.ellipse(
        [circle_margin, circle_margin, size - circle_margin, size - circle_margin],
        fill='white',
        outline='#764ba2',
        width=size // 20
    )
    
    # Try to add text
    try:
        font_size = size // 4
        # Use default font if custom font not available
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
        
        text = "P2P"
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        text_x = (size - text_width) // 2
        text_y = (size - text_height) // 2 - font_size // 8
        
        draw.text((text_x, text_y), text, fill='#667eea', font=font)
    except Exception as e:
        print(f"Could not add text: {e}")
    
    # Save image
    img.save(output_path, 'PNG')
    print(f"Created icon: {output_path}")

# Create icons directory if it doesn't exist
icons_dir = 'static/icons'
os.makedirs(icons_dir, exist_ok=True)

# Create 192x192 icon
create_icon(192, os.path.join(icons_dir, 'icon-192.png'))

# Create 512x512 icon
create_icon(512, os.path.join(icons_dir, 'icon-512.png'))

print("Icons created successfully!")
