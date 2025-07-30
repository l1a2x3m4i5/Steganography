from flask import Flask, render_template, request, flash
from flask import send_from_directory
from werkzeug.utils import secure_filename
from PIL import Image
import os
import random
import string
import time
import wave
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

app = Flask(__name__)
app.secret_key = "supersecretkey"  # For flash messages
UPLOAD_FOLDER = "uploads/"
EXPIRE_FILE_TIME = 5 * 60  # Expiration time (5 mins) in seconds
EXPIRE_KEY_TIME = 3 * 60  # Expiration time for key and message in seconds (3 mins)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Helper function to generate a random alphanumeric key with expiration time
def generate_key(length=16, expiry_time=EXPIRE_KEY_TIME):
    random_key = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    expiration_time = time.time() + expiry_time
    key = f"{random_key}|{expiration_time}"
    sanitized_key = key.replace('|', '_')  # Replace '|' for filename safety
    return sanitized_key, key

# AES encryption and decryption
def aes_encrypt(message, key):
    actual_key = key.split("|")[0]
    cipher = AES.new(actual_key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def aes_decrypt(encrypted_message, key):
    actual_key = key.split("|")[0]
    iv = b64decode(encrypted_message[:24])
    ct = b64decode(encrypted_message[24:])
    cipher = AES.new(actual_key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return decrypted

# DES encryption and decryption
def des_encrypt(message, key):
    actual_key = key.split("|")[0][:8]  # DES requires 8-byte keys
    cipher = DES.new(actual_key.encode('utf-8'), DES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), DES.block_size))
    return b64encode(ct_bytes).decode('utf-8')

def des_decrypt(encrypted_message, key):
    actual_key = key.split("|")[0][:8]
    cipher = DES.new(actual_key.encode('utf-8'), DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(b64decode(encrypted_message)), DES.block_size)
    return decrypted.decode('utf-8')

# LSB steganography for images
def encode_message(image_path, output_path, message, key):
    image = Image.open(image_path)
    encoded_image = image.copy()
    width, height = image.size
    message += '|END|'
    binary_message = ''.join([f"{ord(char):08b}" for char in message])
    binary_key = ''.join([f"{ord(char):08b}" for char in key])

    if len(binary_message) + len(binary_key) > width * height * 3:  # 3 for RGB channels
        raise ValueError("Message and key too large to encode in the image")

    pixels = list(encoded_image.getdata())
    idx = 0
    for i in range(len(pixels)):
        pixel = list(pixels[i])
        for j in range(len(pixel)):
            if idx < len(binary_key + binary_message):
                pixel[j] = (pixel[j] & ~1) | int((binary_key + binary_message)[idx])
                idx += 1
        pixels[i] = tuple(pixel)

    encoded_image.putdata(pixels)
    encoded_image.save(output_path)

def decode_message(image_path, key):
    image = Image.open(image_path)
    binary_data = ""
    pixels = list(image.getdata())
    for pixel in pixels:
        for color in pixel:
            binary_data += str(color & 1)

    binary_key_len = len(key) * 8
    binary_key = binary_data[:binary_key_len]
    decoded_key = ''.join([chr(int(binary_key[i:i+8], 2)) for i in range(0, len(binary_key), 8)])
    if decoded_key != key:
        raise ValueError("Invalid key provided")

    binary_message = binary_data[binary_key_len:]
    decoded_message = ''.join([chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)])
    if '|END|' not in decoded_message:
        raise ValueError("No valid message found")

    return decoded_message.split('|END|')[0]

# LSB steganography for audio
def encode_audio(audio_path, output_path, message, key):
    with wave.open(audio_path, "rb") as audio:
        params = audio.getparams()
        frames = bytearray(list(audio.readframes(audio.getnframes())))

    message += "|END|"
    binary_message = ''.join([f"{ord(char):08b}" for char in message])
    binary_key = ''.join([f"{ord(char):08b}" for char in key])

    if len(binary_message) + len(binary_key) > len(frames):
        raise ValueError("Message and key too large to encode in the audio file")

    idx = 0
    for i in range(len(frames)):
        if idx < len(binary_key + binary_message):
            frames[i] = (frames[i] & ~1) | int((binary_key + binary_message)[idx])
            idx += 1

    with wave.open(output_path, "wb") as output:
        output.setparams(params)
        output.writeframes(bytes(frames))

def decode_audio(audio_path, key):
    with wave.open(audio_path, "rb") as audio:
        frames = list(audio.readframes(audio.getnframes()))

    binary_data = ''.join([str(frame & 1) for frame in frames])

    binary_key_len = len(key) * 8
    binary_key = binary_data[:binary_key_len]
    decoded_key = ''.join([chr(int(binary_key[i:i+8], 2)) for i in range(0, len(binary_key), 8)])
    if decoded_key != key:
        raise ValueError("Invalid key provided")

    binary_message = binary_data[binary_key_len:]
    decoded_message = ''.join([chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)])
    if '|END|' not in decoded_message:
        raise ValueError("No valid message found")

    return decoded_message.split('|END|')[0]

# Helper function to check if a file has expired
def is_file_expired(file_path):
    file_creation_time = os.path.getctime(file_path)
    return time.time() - file_creation_time > EXPIRE_FILE_TIME

# Routes
@app.route("/")
def home():
    return render_template("base.html")

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    form_data = {}
    if request.method == "POST":
        form_data = request.form.to_dict()  # Retain submitted form data
        try:
            file = request.files.get("file")
            message = form_data.get("message")
            encryption_type = form_data.get("encryption_type")

            if not message:
                raise ValueError("Message is required for encryption.")

            # Check if the key already exists
            key_sanitized, key = generate_key()
            key_filename = f"key_{key_sanitized}.txt"
            key_path = os.path.join(UPLOAD_FOLDER, key_filename)

            if not os.path.exists(key_path):  # Avoid creating a new key if it already exists
                with open(key_path, "w") as key_file:
                    key_file.write(key)

            encrypted_message = ""
            if encryption_type == "AES":
                encrypted_message = aes_encrypt(message, key)
            elif encryption_type == "DES":
                encrypted_message = des_encrypt(message, key)
            elif file:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)

                if file.filename.lower().endswith(("png", "jpg", "jpeg")):
                    output_image_path = os.path.join(app.config["UPLOAD_FOLDER"], f"encoded_{filename}")
                    encode_message(file_path, output_image_path, message, key)
                    encrypted_message = f"Image saved at: {output_image_path}"
                elif file.filename.lower().endswith("wav"):
                    output_audio_path = os.path.join(app.config["UPLOAD_FOLDER"], f"encoded_{filename}")
                    encode_audio(file_path, output_audio_path, message, key)
                    encrypted_message = f"Audio saved at: {output_audio_path}"
                else:
                    raise ValueError("Unsupported file type.")
            else:
                raise ValueError("Invalid encryption type or missing file.")

            return render_template(
                "encryptMedia.html",
                key_file=key_path,
                encrypted_message=encrypted_message,
                form_data=form_data,  # Ensure form_data is always passed
                success=True,
            )
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return render_template("encryptMedia.html", form_data=form_data, success=False)
    return render_template("encryptMedia.html", success=False, form_data=form_data)  # Pass form_data even on GET

@app.route("/decrypt", methods=["GET", "POST"])
@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    form_data = {}  # Default to an empty dictionary to avoid undefined errors in the template
    decrypted_file_path = None  # Track path for the decrypted file (image or audio)
    if request.method == "POST":
        form_data = request.form.to_dict()  # Retain submitted form data
        try:
            file = request.files.get("file")
            key_file = request.files.get("key_file")
            encrypted_message = form_data.get("encrypted_message", "")
            decryption_type = form_data.get("decryption_type")

            if not key_file:
                raise ValueError("Key file is required for decryption.")

            key_filename = secure_filename(key_file.filename)
            key_path = os.path.join(app.config["UPLOAD_FOLDER"], key_filename)

            # Check if key file already exists; do not create duplicates
            if not os.path.exists(key_path):
                key_file.save(key_path)

            with open(key_path, "r") as key_file_content:
                key = key_file_content.read().strip()

            if not key or "|" not in key:
                raise ValueError("Invalid key format.")

            if time.time() - os.path.getctime(key_path) > EXPIRE_KEY_TIME:
                raise ValueError("The encryption key has expired.")

            decrypted_message = ""
            if decryption_type == "AES":
                decrypted_message = aes_decrypt(encrypted_message, key)
            elif decryption_type == "DES":
                decrypted_message = des_decrypt(encrypted_message, key)
            elif file:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)

                if is_file_expired(file_path):
                    raise ValueError("The uploaded file has expired.")

                if decryption_type == "Audio" and file.filename.lower().endswith("wav"):
                    decrypted_message = decode_audio(file_path, key)
                    decrypted_file_path = file_path
                elif decryption_type == "LSB" and file.filename.lower().endswith(("png", "jpg", "jpeg")):
                    decrypted_message = decode_message(file_path, key)
                    decrypted_file_path = file_path
                else:
                    raise ValueError("Invalid decryption type or unsupported file type.")
            else:
                raise ValueError("Invalid decryption type or missing file.")

            return render_template(
                "decryptMedia.html",
                success=True,
                decrypted_message=decrypted_message,
                form_data=form_data,
                decrypted_file_path=decrypted_file_path,
                key_filename=key_filename,
            )
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return render_template("decryptMedia.html", form_data=form_data, success=False)

    return render_template("decryptMedia.html", success=False, form_data=form_data)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == "__main__":
    app.run(debug=True)