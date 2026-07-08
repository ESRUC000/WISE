import tkinter as tk
from tkinter import ttk
import fil_scanner

def sfn():
    # Get fresh scan results
    networks = fil_scanner.scan()

    # Clear previous rows
    for row in tree.get_children():
        tree.delete(row)

    # Add new rows
    for network in networks:
        tree.insert(
            "",
            tk.END,
            values=(
                network["ssid"],
                network["signal"],
                network["encryption"]
            )
        )


# Create window
root = tk.Tk()
root.title("WISE")
root.geometry("700x400")

# Scan button
button = tk.Button(root, text="Scan", command=sfn)
button.pack(pady=10)

# Create table
tree = ttk.Treeview(
    root,
    columns=("SSID", "Signal", "Encryption"),
    show="headings"
)

# Headings
tree.heading("SSID", text="SSID")
tree.heading("Signal", text="Signal")
tree.heading("Encryption", text="Encryption")

# Column widths
tree.column("SSID", width=300)
tree.column("Signal", width=100, anchor="center")
tree.column("Encryption", width=120, anchor="center")
# Show table
tree.pack(fill="both", expand=True, padx=10, pady=10)

# Set dark background for the window
root.configure(bg="#2e2e2e")  # Dark gray

# Start application
root.mainloop()