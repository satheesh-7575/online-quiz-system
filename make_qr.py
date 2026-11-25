import qrcode

# Replace with your computer’s IP (from ipconfig)
server_url = "http://192.168.1.25:5000"

img = qrcode.make(server_url)
img.save("server_qr.png")
print("QR code saved as server_qr.png")
