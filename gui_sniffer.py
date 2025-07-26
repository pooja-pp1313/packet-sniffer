import tkinter as tk
from tkinter import ttk
import sqlite3
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def get_protocol_data():
    conn = sqlite3.connect('packets.db')
    cursor = conn.cursor()

    cursor.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
    data = cursor.fetchall()
    conn.close()

    labels = [row[0] for row in data]
    sizes = [row[1] for row in data]

    return labels, sizes

def update_chart():
    labels, sizes = get_protocol_data()

    ax.clear()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%')
    ax.set_title("Live Protocol Usage")

    canvas.draw()

    root.after(5000, update_chart)  # refresh every 5 seconds

# --- GUI SETUP ---
root = tk.Tk()
root.title("Network Sniffer Dashboard")
root.geometry("600x500")

fig, ax = plt.subplots(figsize=(5, 4))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

update_chart()

root.mainloop()
