from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
PNG_PATH = ROOT / "dalfox-gui-icon.png"
ICO_PATH = ROOT / "dalfox-gui-icon.ico"

size = 256
image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
draw = ImageDraw.Draw(image)

draw.rounded_rectangle(
    (9, 9, 247, 247),
    radius=50,
    fill=(7, 23, 39, 255),
    outline=(34, 211, 238, 255),
    width=10,
)

# Stylized fox head.
draw.polygon(
    [(48, 73), (90, 28), (107, 91), (149, 91), (166, 28), (208, 73)],
    fill=(249, 115, 22, 255),
)
draw.polygon(
    [(56, 77), (205, 77), (184, 164), (128, 214), (72, 164)],
    fill=(251, 146, 60, 255),
)
draw.polygon(
    [(72, 143), (184, 143), (128, 210)],
    fill=(255, 237, 213, 255),
)
draw.polygon(
    [(88, 116), (116, 126), (92, 134)],
    fill=(7, 23, 39, 255),
)
draw.polygon(
    [(168, 116), (140, 126), (164, 134)],
    fill=(7, 23, 39, 255),
)
draw.ellipse((119, 168, 137, 184), fill=(7, 23, 39, 255))

font = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", 58)
text = "GUI"
box = draw.textbbox((0, 0), text, font=font)
text_x = (size - (box[2] - box[0])) // 2
draw.rounded_rectangle(
    (61, 201, 195, 235),
    radius=12,
    fill=(7, 23, 39, 235),
)
draw.text(
    (text_x, 195),
    text,
    font=font,
    fill=(232, 243, 255, 255),
    stroke_width=2,
    stroke_fill=(7, 23, 39, 255),
)

image.save(PNG_PATH, format="PNG")
image.save(
    ICO_PATH,
    format="ICO",
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
)
print(PNG_PATH)
print(ICO_PATH)
