import math
import tkinter as tk

SHIELD = "#0A2463"
WIFI = "#0EA5D9"


def draw_logo(canvas, x=0, y=0, size=120, bg="white", shield=SHIELD, wifi=WIFI):
    """Draw the WISE logo with its top-left corner at (x, y). `size` is the height in pixels."""
    k = size / 120

    def P(px, py):  # logo units (100 x 120) -> canvas pixels
        return x + px * k, y + py * k

    # Shield (doubled points keep the top/bottom tips and corners sharp)
    pts = [(50, 2), (50, 2), (75, 16), (98, 22), (98, 22), (98, 60), (88, 90),
           (50, 118), (50, 118), (12, 90), (2, 60), (2, 22), (2, 22), (25, 16)]
    canvas.create_polygon([c for p in pts for c in P(*p)], smooth=True, fill=bg,
                          outline=shield, width=6 * k, joinstyle="round")

    # Wi-Fi arcs, centred on the dot
    cx, cy = 50, 78
    for r in (40, 22):
        arc = [P(cx + r * math.cos(math.radians(a)), cy - r * math.sin(math.radians(a)))
               for a in range(40, 141, 5)]
        canvas.create_line([c for p in arc for c in p], smooth=True, fill=wifi,
                           width=9 * k, capstyle="round", joinstyle="round")

    # Dot
    x0, y0 = P(cx - 9, cy - 9)
    x1, y1 = P(cx + 9, cy + 9)
    canvas.create_oval(x0, y0, x1, y1, fill=wifi, outline="")


if __name__ == "__main__":
    root = tk.Tk()
    root.title("WISE logo")
    canvas = tk.Canvas(root, width=300, height=340, bg="white", highlightthickness=0)
    canvas.pack()
    draw_logo(canvas, x=75, y=40, size=260)
    root.mainloop()